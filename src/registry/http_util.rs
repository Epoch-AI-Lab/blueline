//! Shared registry HTTP plumbing: URL validation, SSRF guards, capped
//! redirect following, and bounded response reads. Registries delegate here;
//! nothing in this module knows about packuments or checksums.

use std::io::Read;

use ureq::Agent;

use crate::error::BluelineError;

#[derive(Debug, Clone, Copy)]
pub struct RegistryLimits {
    pub max_packument_bytes: u64,
    pub max_tarball_bytes: u64,
    pub max_redirects: usize,
}

impl Default for RegistryLimits {
    fn default() -> Self {
        Self {
            max_packument_bytes: 64 * 1024 * 1024,
            max_tarball_bytes: 512 * 1024 * 1024,
            max_redirects: 5,
        }
    }
}

/// Validate that a download URL is scheme-compatible with the registry base
/// and does not bounce a public registry base onto a private/local host.
pub fn validate_download_url(base: &str, download_url: &str) -> Result<(), BluelineError> {
    let (download_scheme, download_host) =
        parse_url_scheme_and_host(download_url).map_err(|e| {
            BluelineError::Network(format!("invalid download URL `{download_url}`: {e}"))
        })?;

    let (base_scheme, base_host) = parse_url_scheme_and_host(base)
        .map_err(|e| BluelineError::Network(format!("invalid registry base URL `{base}`: {e}")))?;

    if base_scheme == "https" {
        if download_scheme != "https" {
            return Err(BluelineError::Network(format!(
                "insecure download scheme `{download_scheme}` in `{download_url}`; registry base requires HTTPS"
            )));
        }
    } else if base_scheme == "http" {
        match download_scheme.as_str() {
            "http" | "https" => {}
            _ => {
                return Err(BluelineError::Network(format!(
                    "unsupported download scheme `{download_scheme}` in `{download_url}`"
                )));
            }
        }
    } else {
        return Err(BluelineError::Network(format!(
            "unsupported registry base scheme `{base_scheme}` in `{base}`"
        )));
    }

    if is_private_or_local_host(&download_host) && base_host != download_host {
        return Err(BluelineError::Network(format!(
            "download URL `{download_url}` targets private/local host `{download_host}`, which does not match registry base host `{base_host}`"
        )));
    }

    Ok(())
}

/// Follow a capped redirect loop (validating every hop) and read at most
/// `max_bytes` bytes of the final response body.
pub fn download_bounded(
    agent: &Agent,
    base: &str,
    url: &str,
    max_bytes: u64,
    max_redirects: usize,
) -> Result<Vec<u8>, BluelineError> {
    let mut current_url = url.to_string();
    let mut redirects_followed = 0;

    let resp = loop {
        validate_download_url(base, &current_url)?;
        let res = agent.get(&current_url).call();
        match res {
            Ok(response) if (301..=308).contains(&response.status()) => {
                redirects_followed += 1;
                if redirects_followed > max_redirects {
                    return Err(BluelineError::Network(format!(
                        "too many redirects downloading {url}"
                    )));
                }
                let location = response.header("location").ok_or_else(|| {
                    BluelineError::Network(format!(
                        "redirect {} missing Location header for {current_url}",
                        response.status()
                    ))
                })?;
                current_url = resolve_redirect_url(&current_url, location)?;
            }
            Ok(response) => break response,
            Err(e) => {
                return Err(BluelineError::Network(format!("GET {url}: {e}")));
            }
        }
    };

    let mut bytes = Vec::new();
    let mut reader = resp.into_reader().take(max_bytes + 1);
    reader
        .read_to_end(&mut bytes)
        .map_err(|e| BluelineError::Network(format!("downloading {url}: {e}")))?;

    if bytes.len() as u64 > max_bytes {
        return Err(BluelineError::ExtractionLimit(format!(
            "response exceeds maximum size cap of {max_bytes} bytes"
        )));
    }

    Ok(bytes)
}

pub fn resolve_redirect_url(base_url: &str, location: &str) -> Result<String, BluelineError> {
    if location.contains("://") {
        return Ok(location.to_string());
    }
    let (scheme, _host) = parse_url_scheme_and_host(base_url).map_err(|e| {
        BluelineError::Network(format!(
            "resolving redirect `{location}` from `{base_url}`: {e}"
        ))
    })?;
    let base_without_scheme = base_url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(base_url);
    let authority = base_without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    if location.starts_with('/') {
        Ok(format!("{scheme}://{authority}{location}"))
    } else {
        let path_part = match base_without_scheme.split_once('/') {
            Some((_, rest)) => {
                let p = rest.split(['?', '#']).next().unwrap_or("");
                if let Some((dir, _)) = p.rsplit_once('/') {
                    format!("/{dir}/")
                } else {
                    "/".to_string()
                }
            }
            None => "/".to_string(),
        };
        Ok(format!("{scheme}://{authority}{path_part}{location}"))
    }
}

pub fn parse_url_scheme_and_host(raw_url: &str) -> Result<(String, String), String> {
    let (scheme, rest) = raw_url
        .split_once("://")
        .ok_or_else(|| format!("URL `{raw_url}` is missing `://` scheme separator"))?;
    let scheme = scheme.to_lowercase();
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(format!("URL `{raw_url}` has empty host"));
    }
    let host_port = if let Some((_, hp)) = authority.rsplit_once('@') {
        hp
    } else {
        authority
    };
    let host = if host_port.starts_with('[') {
        let closing = host_port
            .find(']')
            .ok_or_else(|| format!("URL `{raw_url}` has unmatched `[` in IPv6 address"))?;
        &host_port[1..closing]
    } else if let Some((h, _port)) = host_port.split_once(':') {
        h
    } else {
        host_port
    };
    if host.is_empty() {
        return Err(format!("URL `{raw_url}` has empty host"));
    }
    Ok((scheme, host.to_lowercase()))
}

fn is_private_v4(v4: std::net::Ipv4Addr) -> bool {
    let octets = v4.octets();
    octets[0] == 0 // 0.0.0.0/8 (This host on this network / Linux localhost alias)
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_private()
        || v4.is_unspecified()
        || v4.is_broadcast()
        // CGNAT RFC 6598 (100.64.0.0/10)
        || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
}

fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_private_v4(v4),
        std::net::IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            if (seg0 & 0xff00) == 0xff00 // Multicast (ff00::/8)
                || (seg0 & 0xffc0) == 0xfe80 // Link-local (fe80::/10)
                || (seg0 & 0xfe00) == 0xfc00 // Unique local (fc00::/7)
                || seg0 == 0x0100 // Discard prefix (100::/64)
                || (seg0 == 0x2001 && v6.segments()[1] == 0x0db8)
            // Documentation (2001:db8::/32)
            {
                return true;
            }
            if let Some(v4) = v6.to_ipv4() {
                return is_private_v4(v4);
            }
            false
        }
    }
}

fn is_special_local_domain(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "metadata.google.internal"
        || host == "instance-data"
}

fn is_non_canonical_ip(host: &str) -> bool {
    if host.eq_ignore_ascii_case("0x")
        || host.starts_with("0x")
        || host.starts_with("0X")
        || host.contains(".0x")
        || host.contains(".0X")
    {
        return true;
    }
    if !host.is_empty() && host.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    let mut part_count = 0;
    let mut has_leading_zero = false;
    let mut all_digits = true;

    for p in host.split('.') {
        part_count += 1;
        if p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) {
            all_digits = false;
        } else if p.len() > 1 && p.starts_with('0') {
            has_leading_zero = true;
        }
    }

    all_digits && (part_count != 4 || has_leading_zero)
}

pub fn is_private_or_local_host(host: &str) -> bool {
    if is_special_local_domain(host) || is_non_canonical_ip(host) {
        return true;
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return is_private_ip(ip);
    }

    // Resolve hostname to IP to prevent DNS rebinding or hostname-based SSRF
    use std::net::ToSocketAddrs;
    if let Ok(addrs) = (host, 443).to_socket_addrs() {
        for socket_addr in addrs {
            if is_private_ip(socket_addr.ip()) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_download_url_ssrf_and_schemes() {
        let base = "https://registry.npmjs.org";

        // Public https is valid
        assert!(
            validate_download_url(
                base,
                "https://registry.npmjs.org/express/-/express-4.21.2.tgz"
            )
            .is_ok()
        );
        assert!(validate_download_url(base, "https://cdn.example.com/express.tgz").is_ok());

        // Insecure http rejected when base is https
        assert!(validate_download_url(base, "http://registry.npmjs.org/express.tgz").is_err());

        // Localhost / Loopback rejected
        assert!(validate_download_url(base, "https://127.0.0.1/express.tgz").is_err());
        assert!(validate_download_url(base, "https://localhost/express.tgz").is_err());
        assert!(validate_download_url(base, "https://[::1]/express.tgz").is_err());

        // Cloud metadata rejected
        assert!(validate_download_url(base, "https://169.254.169.254/latest/meta-data").is_err());
        assert!(
            validate_download_url(base, "https://metadata.google.internal/computeMetadata")
                .is_err()
        );

        // RFC 1918 private IPs rejected
        assert!(validate_download_url(base, "https://10.0.0.1/tarball.tgz").is_err());
        assert!(validate_download_url(base, "https://192.168.1.50/tarball.tgz").is_err());
        assert!(validate_download_url(base, "https://172.16.0.10/tarball.tgz").is_err());

        // Local registry allows matching local host
        let local_base = "http://127.0.0.1:8080";
        assert!(
            validate_download_url(
                local_base,
                "http://127.0.0.1:8080/express/-/express-1.0.0.tgz"
            )
            .is_ok()
        );
        assert!(
            validate_download_url(
                local_base,
                "https://127.0.0.1:8080/express/-/express-1.0.0.tgz"
            )
            .is_ok()
        );
        assert!(
            validate_download_url(
                local_base,
                "ftp://127.0.0.1:8080/express/-/express-1.0.0.tgz"
            )
            .is_err()
        );
        assert!(validate_download_url(local_base, "file:///etc/passwd").is_err());
        let ftp_base = "ftp://127.0.0.1:8080";
        assert!(validate_download_url(ftp_base, "ftp://127.0.0.1:8080/pkg.tgz").is_err());
        // But local registry cannot be bounced to metadata
        assert!(
            validate_download_url(local_base, "http://169.254.169.254/latest/meta-data").is_err()
        );
    }

    #[test]
    fn is_private_or_local_host_covers_all_ranges() {
        assert!(is_private_or_local_host("localhost"));
        assert!(is_private_or_local_host("foo.localhost"));
        assert!(is_private_or_local_host("metadata.google.internal"));
        assert!(is_private_or_local_host("instance-data"));
        assert!(is_private_or_local_host("127.0.0.1"));
        assert!(is_private_or_local_host("169.254.169.254"));
        assert!(is_private_or_local_host("10.0.0.1"));
        assert!(is_private_or_local_host("172.16.0.1"));
        assert!(is_private_or_local_host("192.168.1.1"));
        assert!(is_private_or_local_host("0.0.0.0"));
        assert!(is_private_or_local_host("255.255.255.255"));
        assert!(is_private_or_local_host("::1"));
        assert!(is_private_or_local_host("fe80::1"));
        assert!(is_private_or_local_host("fc00::1"));
        assert!(is_private_or_local_host("fd00::1"));
        assert!(is_private_or_local_host("::ffff:127.0.0.1"));
        assert!(is_private_or_local_host("::ffff:169.254.169.254"));
        assert!(is_private_or_local_host("::ffff:10.0.0.1"));
        assert!(is_private_or_local_host("100.64.0.1"));
        assert!(is_private_or_local_host("100.127.255.254"));
        assert!(is_private_or_local_host("ff02::1"));
        assert!(is_private_or_local_host("ff02::2"));
        assert!(is_private_or_local_host("2001:db8::1"));
        assert!(is_private_or_local_host("100::1"));

        assert!(!is_private_or_local_host("registry.npmjs.org"));
        assert!(!is_private_or_local_host("8.8.8.8"));
        assert!(!is_private_or_local_host("1.1.1.1"));
        assert!(!is_private_or_local_host("100.63.255.255"));
        assert!(!is_private_or_local_host("100.128.0.1"));
        assert!(!is_private_or_local_host("2607:f8b0:4005:805::200e"));
        assert!(!is_private_or_local_host("2001:cafe::1"));
        assert!(!is_private_or_local_host("2002:db8::1"));

        // Direct is_private_ip invariant checks
        assert!(is_private_ip("::1".parse().unwrap()));
        assert!(is_private_ip("::".parse().unwrap()));
        assert!(!is_private_ip("2001:cafe::1".parse().unwrap()));
        assert!(!is_private_ip("2002:db8::1".parse().unwrap()));
    }

    #[test]
    fn special_local_domain_and_non_canonical_ip_tests() {
        assert!(is_special_local_domain("localhost"));
        assert!(is_special_local_domain("sub.localhost"));
        assert!(is_special_local_domain("metadata.google.internal"));
        assert!(is_special_local_domain("instance-data"));
        assert!(!is_special_local_domain("registry.npmjs.org"));
        assert!(!is_special_local_domain("notlocalhost"));

        assert!(is_non_canonical_ip("0x7f000001"));
        assert!(is_non_canonical_ip("0X7F000001"));
        assert!(is_non_canonical_ip("127.0x0.0.1"));
        assert!(is_non_canonical_ip("127.0X0.0.1"));
        assert!(is_non_canonical_ip("2130706433"));
        assert!(is_non_canonical_ip("127.1"));
        assert!(is_non_canonical_ip("0177.0.0.1"));

        assert!(!is_non_canonical_ip(""));
        assert!(!is_non_canonical_ip("127.0.0.1"));
        assert!(!is_non_canonical_ip("8.8.8.8"));
        assert!(!is_non_canonical_ip("127.0..1"));
        assert!(!is_non_canonical_ip("registry.npmjs.org"));
    }

    #[test]
    fn ssrf_rejects_alternative_encodings_and_ranges() {
        assert!(is_private_or_local_host("0.0.0.0"));
        assert!(is_private_or_local_host("0.0.0.1"));
        assert!(is_private_or_local_host("0.42.42.42"));
        assert!(is_private_or_local_host("127.0.0.1"));
        assert!(is_private_or_local_host("10.0.0.1"));
        assert!(is_private_or_local_host("169.254.169.254"));
        assert!(is_private_or_local_host("0x7f000001"));
        assert!(is_private_or_local_host("0X7F000001"));
        assert!(is_private_or_local_host("127.0x0.0.1"));
        assert!(is_private_or_local_host("127.0X0.0.1"));
        assert!(is_private_or_local_host("0177.0.0.1"));
        assert!(is_private_or_local_host("2130706433"));
        assert!(is_private_or_local_host("127.1"));
        assert!(is_private_or_local_host("::1"));
        assert!(is_private_or_local_host("::127.0.0.1"));
        assert!(is_private_or_local_host("::ffff:127.0.0.1"));
        assert!(is_private_or_local_host("::10.0.0.1"));
        assert!(is_private_or_local_host("::172.16.0.1"));
        assert!(is_private_or_local_host("::192.168.1.1"));
        assert!(is_private_or_local_host("metadata.google.internal"));
        assert!(is_private_or_local_host("instance-data"));
        assert!(is_private_or_local_host("localhost"));
        assert!(is_private_or_local_host("sub.localhost"));

        assert!(!is_private_or_local_host("registry.npmjs.org"));
        assert!(!is_private_or_local_host("8.8.8.8"));
        assert!(!is_private_or_local_host("1.1.1.1"));
        assert!(!is_private_or_local_host("::8.8.8.8"));
        assert!(!is_private_or_local_host("::1.1.1.1"));
    }

    #[test]
    fn relative_redirect_resolution() {
        let base = "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz";
        assert_eq!(
            resolve_redirect_url(base, "/downloads/pkg-1.0.0.tgz").unwrap(),
            "https://registry.npmjs.org/downloads/pkg-1.0.0.tgz"
        );
        assert_eq!(
            resolve_redirect_url(base, "relative.tgz").unwrap(),
            "https://registry.npmjs.org/pkg/-/relative.tgz"
        );
        assert_eq!(
            resolve_redirect_url(base, "https://cdn.npmjs.org/pkg.tgz").unwrap(),
            "https://cdn.npmjs.org/pkg.tgz"
        );
    }
}
