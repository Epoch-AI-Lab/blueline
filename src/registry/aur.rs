use crate::error::BluelineError;
use crate::registry::http_util::RegistryLimits;
use serde::Deserialize;
use std::io::Read;
use ureq::Agent;

const USER_AGENT: &str = concat!("blueline/", env!("CARGO_PKG_VERSION"));
const RPC_VERSION: u8 = 5;

/// AUR RPC v5 metadata for one package (the `multiinfo` result shape).
/// Required fields fail closed on absence; optional fields are `None` when
/// the AUR omits or nulls them (e.g. `Maintainer` is null for orphans).
#[derive(Debug, Clone, Deserialize)]
pub struct AurInfo {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "PackageBase")]
    pub package_base: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Description")]
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "URL")]
    #[serde(default)]
    pub url: Option<String>,
    #[serde(rename = "NumVotes")]
    #[serde(default)]
    pub num_votes: Option<u64>,
    #[serde(rename = "Popularity")]
    #[serde(default)]
    pub popularity: Option<f64>,
    /// Unix timestamp when the package was flagged out-of-date, if it is.
    #[serde(rename = "OutOfDate")]
    #[serde(default)]
    pub out_of_date: Option<u64>,
    /// Null means the package is orphaned.
    #[serde(rename = "Maintainer")]
    #[serde(default)]
    pub maintainer: Option<String>,
    #[serde(rename = "FirstSubmitted")]
    #[serde(default)]
    pub first_submitted: Option<u64>,
    #[serde(rename = "LastModified")]
    #[serde(default)]
    pub last_modified: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct AurRpcResponse {
    #[serde(rename = "version")]
    #[allow(dead_code)]
    version: u8,
    #[serde(rename = "type")]
    result_type: String,
    #[serde(rename = "resultcount")]
    result_count: u32,
    #[serde(rename = "results")]
    results: Vec<AurInfo>,
}

/// AUR names are lowercase alphanumerics plus `.@_+-`, bounded to 255 bytes,
/// and must start and end alphanumeric (the makepkg pkgname grammar,
/// restricted to what the AUR actually hosts).
pub fn validate_aur_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    name.chars().all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '+' | '-' | '@')
    })
}

/// Percent-encode a validated AUR name for use as a query value, so names
/// containing `+` or `@` cannot shift the query-string structure.
fn encode_query_value(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for b in name.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Client for the AUR RPC v5 metadata interface
/// (https://aur.archlinux.org/rpc/v5). Read-only; fetches package metadata
/// and the pkgname → pkgbase mapping. Git history and archive content land
/// with the adapter in a later PR.
pub struct AurRpc {
    agent: Agent,
    base: String,
    limits: RegistryLimits,
}

impl AurRpc {
    pub fn new(base: &str) -> Self {
        Self::with_limits(base, RegistryLimits::default())
    }

    pub fn with_limits(base: &str, limits: RegistryLimits) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(90))
            .user_agent(USER_AGENT)
            .redirects(0)
            .build();
        Self {
            agent,
            base: base.trim_end_matches('/').to_string(),
            limits,
        }
    }

    /// Fetch RPC metadata for one package name. The returned `AurInfo::name`
    /// is compared verbatim against the request; a mismatch fails closed.
    pub fn info(&self, name: &str) -> Result<AurInfo, BluelineError> {
        if !validate_aur_name(name) {
            return Err(BluelineError::InvalidPackageSpec(format!(
                "`{name}` invalid AUR package name"
            )));
        }
        let url = format!(
            "{}/rpc/v5/info?arg%5B%5D={}",
            self.base,
            encode_query_value(name)
        );
        let resp = match self.agent.get(&url).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(404, _)) => {
                return Err(BluelineError::Manifest(
                    name.to_string(),
                    "not found".into(),
                ));
            }
            Err(e) => return Err(BluelineError::Network(format!("GET {url}: {e}"))),
        };
        if resp
            .header("content-type")
            .is_some_and(|ct| !ct.to_ascii_lowercase().contains("json"))
        {
            return Err(BluelineError::Manifest(
                name.to_string(),
                "bad content-type".into(),
            ));
        }
        let mut body = String::new();
        resp.into_reader()
            .take(self.limits.max_packument_bytes + 1)
            .read_to_string(&mut body)
            .map_err(|e| BluelineError::Network(format!("{e}")))?;
        if body.len() as u64 > self.limits.max_packument_bytes {
            return Err(BluelineError::ExtractionLimit(format!(
                "cap {}",
                self.limits.max_packument_bytes
            )));
        }
        let parsed: AurRpcResponse = serde_json::from_str(&body)
            .map_err(|e| BluelineError::Manifest(name.to_string(), format!("bad json: {e}")))?;
        if parsed.version != RPC_VERSION {
            return Err(BluelineError::Manifest(
                name.to_string(),
                format!("unsupported RPC version {}", parsed.version),
            ));
        }
        if parsed.result_type != "multiinfo" {
            return Err(BluelineError::Manifest(
                name.to_string(),
                format!("unexpected RPC result type `{}`", parsed.result_type),
            ));
        }
        if parsed.result_count as usize != parsed.results.len() {
            return Err(BluelineError::Manifest(
                name.to_string(),
                "resultcount does not match results".into(),
            ));
        }
        if parsed.results.len() > 1 {
            return Err(BluelineError::Manifest(
                name.to_string(),
                "expected exactly one result for an exact-name lookup".into(),
            ));
        }
        let info = parsed.results.into_iter().next().ok_or_else(|| {
            BluelineError::Manifest(name.to_string(), "not found in AUR".to_string())
        })?;
        if info.name != name {
            return Err(BluelineError::Manifest(
                name.to_string(),
                format!("registry returned name `{}` instead", info.name),
            ));
        }
        if !validate_aur_name(&info.package_base) {
            return Err(BluelineError::Manifest(
                name.to_string(),
                format!(
                    "registry returned invalid PackageBase `{}`",
                    info.package_base
                ),
            ));
        }
        Ok(info)
    }

    /// The git repository / package base that owns this package name. Split
    /// packages share a pkgbase; every repo-level operation must address it.
    pub fn pkgbase(&self, name: &str) -> Result<String, BluelineError> {
        Ok(self.info(name)?.package_base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::Arc;

    fn rpc_body(info: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": 5,
            "type": "multiinfo",
            "resultcount": 1,
            "results": [info]
        }))
        .unwrap()
    }

    fn sample_info() -> serde_json::Value {
        serde_json::json!({
            "ID": 100,
            "Name": "yay",
            "PackageBaseID": 101,
            "PackageBase": "yay",
            "Version": "12.4.2-1",
            "Description": "Yet another yogurt",
            "URL": "https://github.com/Jguer/yay",
            "NumVotes": 800,
            "Popularity": 42.5,
            "OutOfDate": null,
            "Maintainer": "Jguer",
            "FirstSubmitted": 1478763459,
            "LastModified": 1735689600,
            "URLPath": "/cgit/aur.git/snapshot/yay.tar.gz"
        })
    }

    struct MockAurServer {
        base: String,
        _handle: std::thread::JoinHandle<()>,
    }

    impl MockAurServer {
        fn spawn<F: Fn(&str) -> (u16, String, Vec<u8>) + Send + Sync + 'static>(
            handler: F,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let handler = Arc::new(handler);
            let handle = std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let h = handler.clone();
                    std::thread::spawn(move || {
                        let mut stream = stream;
                        let mut buf = [0u8; 4096];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let path = req
                            .lines()
                            .next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .unwrap_or("/")
                            .to_string();
                        let (status, ctype, body) = h(&path);
                        let head = format!(
                            "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(&body);
                    });
                }
            });
            Self {
                base,
                _handle: handle,
            }
        }
    }

    #[test]
    fn validate_aur_name_accepts_grammar_and_rejects_the_rest() {
        for ok in [
            "yay",
            "python-pydantic",
            "lib32-mesa",
            "2ping",
            "g_w-k.a+b@1x",
        ] {
            assert!(validate_aur_name(ok), "expected valid: {ok}");
        }
        for bad in [
            "",
            "-yay",
            "yay-",
            ".yay",
            "yay.",
            "+yay",
            "Yay",
            "y ay",
            "yay/",
            "yay?x",
            "yay&x",
            "é",
            "yay\t",
            &"a".repeat(256),
        ] {
            assert!(!validate_aur_name(bad), "expected invalid: {bad}");
        }
        assert!(validate_aur_name(&"a".repeat(255)));
    }

    #[test]
    fn encode_query_value_keeps_url_structure() {
        assert_eq!(encode_query_value("yay"), "yay");
        assert_eq!(encode_query_value("a+b"), "a%2Bb");
        assert_eq!(encode_query_value("a@b.c_d-e"), "a%40b.c_d-e");
    }

    #[test]
    fn info_resolves_metadata_and_pkgbase() {
        let server = MockAurServer::spawn(|path| {
            if path.starts_with("/rpc/v5/info?arg%5B%5D=yay") {
                (200, "application/json".into(), rpc_body(sample_info()))
            } else {
                (404, "text/plain".into(), b"nope".to_vec())
            }
        });
        let rpc = AurRpc::new(&server.base);
        let info = rpc.info("yay").unwrap();
        assert_eq!(info.name, "yay");
        assert_eq!(info.package_base, "yay");
        assert_eq!(info.version, "12.4.2-1");
        assert_eq!(info.num_votes, Some(800));
        assert_eq!(info.maintainer, Some("Jguer".to_string()));
        assert_eq!(info.out_of_date, None);
        assert_eq!(rpc.pkgbase("yay").unwrap(), "yay");
    }

    #[test]
    fn info_handles_split_packages_orphans_and_not_found() {
        let server = MockAurServer::spawn(|path| {
            if path.starts_with("/rpc/v5/info?arg%5B%5D=python-demo") {
                let mut info = sample_info();
                info["Name"] = serde_json::json!("python-demo");
                info["PackageBase"] = serde_json::json!("demo");
                info["Maintainer"] = serde_json::Value::Null;
                (200, "application/json".into(), rpc_body(info))
            } else if path.starts_with("/rpc/v5/info?arg%5B%5D=ghost") {
                (
                    200,
                    "application/json".into(),
                    serde_json::to_vec(&serde_json::json!({
                        "version": 5, "type": "multiinfo",
                        "resultcount": 0, "results": []
                    }))
                    .unwrap(),
                )
            } else {
                (404, "text/plain".into(), b"nope".to_vec())
            }
        });
        let rpc = AurRpc::new(&server.base);
        let info = rpc.info("python-demo").unwrap();
        assert_eq!(info.package_base, "demo");
        assert_eq!(info.maintainer, None);
        assert!(matches!(
            rpc.info("ghost"),
            Err(BluelineError::Manifest(_, _))
        ));
    }

    #[test]
    fn info_fails_closed_on_name_mismatch() {
        let server =
            MockAurServer::spawn(|_| (200, "application/json".into(), rpc_body(sample_info())));
        let rpc = AurRpc::new(&server.base);
        let err = rpc.info("not-yay").unwrap_err();
        assert!(err.to_string().contains("returned name `yay`"));
    }

    #[test]
    fn info_fails_closed_on_bad_rpc_shapes() {
        let cases: Vec<(String, &str)> = vec![
            (
                serde_json::json!({
                    "version": 6, "type": "multiinfo", "resultcount": 1,
                    "results": [sample_info()]
                })
                .to_string(),
                "unsupported RPC version",
            ),
            (
                serde_json::json!({
                    "version": 5, "type": "error", "resultcount": 0, "results": []
                })
                .to_string(),
                "unexpected RPC result type",
            ),
            (
                serde_json::json!({
                    "version": 5, "type": "multiinfo", "resultcount": 3,
                    "results": [sample_info(), sample_info()]
                })
                .to_string(),
                "resultcount does not match",
            ),
            (
                serde_json::json!({
                    "version": 5, "type": "multiinfo", "resultcount": 2,
                    "results": [sample_info(), sample_info()]
                })
                .to_string(),
                "expected exactly one result",
            ),
            (
                serde_json::json!({
                    "version": 5, "type": "multiinfo", "resultcount": 1,
                    "results": [{"Name": "yay", "Version": "1-1"}]
                })
                .to_string(),
                "bad json",
            ),
        ];
        for (body, needle) in cases {
            let server = MockAurServer::spawn(move |_| {
                (200, "application/json".into(), body.clone().into_bytes())
            });
            let rpc = AurRpc::new(&server.base);
            let err = rpc.info("yay").unwrap_err().to_string();
            assert!(err.contains(needle), "expected `{needle}` in `{err}`");
        }
    }

    #[test]
    fn info_fails_closed_on_bad_content_type_and_oversize() {
        let server = MockAurServer::spawn(|_| (200, "text/html".into(), b"<html/>".to_vec()));
        assert!(matches!(
            AurRpc::new(&server.base).info("yay"),
            Err(BluelineError::Manifest(_, _))
        ));

        let big = " ".repeat(4096);
        let server = MockAurServer::spawn(move |_| {
            (
                200,
                "application/json".into(),
                format!("{{\"pad\":\"{big}\"}}").into_bytes(),
            )
        });
        let rpc = AurRpc::with_limits(
            &server.base,
            RegistryLimits {
                max_packument_bytes: 1024,
                ..RegistryLimits::default()
            },
        );
        assert!(matches!(
            rpc.info("yay"),
            Err(BluelineError::ExtractionLimit(_))
        ));
    }

    #[test]
    fn info_rejects_invalid_names_before_any_network_use() {
        let server = MockAurServer::spawn(|_| (200, "application/json".into(), Vec::new()));
        let rpc = AurRpc::new(&server.base);
        assert!(matches!(
            rpc.info("../etc/passwd"),
            Err(BluelineError::InvalidPackageSpec(_))
        ));
    }
}
