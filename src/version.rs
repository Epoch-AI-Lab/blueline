use crate::error::BluelineError;
use std::cmp::Ordering;

/// Seam over version ordering so ecosystems with different version grammars
/// (semver today, PEP 440 later) plug into baseline selection and the store
/// without the engine knowing their details.
pub trait VersionInfo: Clone + PartialEq + Eq + Ord + std::fmt::Debug + Sized {
    /// Strict parse. Fail closed on anything the grammar does not accept.
    fn parse(raw: &str) -> Result<Self, BluelineError>;

    /// Canonical string form used when re-resolving against a registry.
    fn canonical(&self) -> String;

    /// True when this version is a pre-release.
    fn is_prerelease(&self) -> bool;

    /// Whether `self` may serve as the reviewed baseline for `target`:
    /// strictly older, and stable unless the target itself is a pre-release.
    fn baseline_eligible_for(&self, target: &Self) -> bool {
        self < target && (target.is_prerelease() || !self.is_prerelease())
    }
}

impl VersionInfo for semver::Version {
    fn parse(raw: &str) -> Result<Self, BluelineError> {
        semver::Version::parse(raw)
            .map_err(|e| BluelineError::InvalidPackageSpec(format!("`{raw}`: invalid semver: {e}")))
    }

    fn canonical(&self) -> String {
        self.to_string()
    }

    fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

#[derive(Clone, Debug)]
pub struct Pep440Version {
    epoch: u64,
    release: Vec<u64>,
    pre: Option<(PreKind, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
    local: Option<Vec<LocalSegment>>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PreKind {
    A,
    B,
    Rc,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LocalSegment {
    Numeric(u64),
    Str(String),
}

pub fn canonicalize_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut last_was_sep = false;
    for c in lower.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !last_was_sep {
                out.push('-');
                last_was_sep = true;
            }
        } else {
            out.push(c);
            last_was_sep = false;
        }
    }
    out
}

pub fn validate_pypi_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    for &b in bytes {
        if !(b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-') {
            return false;
        }
    }
    true
}

impl Pep440Version {
    fn suffix(&self) -> (i32, u64, i32, u64, i32, u64) {
        let (pre_rank, pre_n) = match &self.pre {
            None => {
                if self.post.is_none() && self.dev.is_some() {
                    (-1, 0)
                } else {
                    (3, 0)
                }
            }
            Some((k, n)) => {
                let r = match k {
                    PreKind::A => 0,
                    PreKind::B => 1,
                    PreKind::Rc => 2,
                };
                (r, *n)
            }
        };
        let post_rank = if self.post.is_none() { 0 } else { 1 };
        let post_n = self.post.unwrap_or(0);
        let dev_rank = if self.dev.is_none() { 1 } else { 0 };
        let dev_n = self.dev.unwrap_or(0);
        (pre_rank, pre_n, post_rank, post_n, dev_rank, dev_n)
    }

    fn trimmed_release(release: &[u64]) -> &[u64] {
        let mut i = release.len();
        while i > 0 && release[i - 1] == 0 {
            i -= 1;
        }
        &release[..i]
    }
}

fn cmp_local_opt(a: &Option<Vec<LocalSegment>>, b: &Option<Vec<LocalSegment>>) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(va), Some(vb)) => {
            let len = va.len().min(vb.len());
            for i in 0..len {
                let ord = cmp_local_segment(&va[i], &vb[i]);
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            va.len().cmp(&vb.len())
        }
    }
}

fn cmp_local_segment(a: &LocalSegment, b: &LocalSegment) -> Ordering {
    match (a, b) {
        (LocalSegment::Numeric(n1), LocalSegment::Numeric(n2)) => n1.cmp(n2),
        (LocalSegment::Str(s1), LocalSegment::Str(s2)) => s1.cmp(s2),
        (LocalSegment::Numeric(_), LocalSegment::Str(_)) => Ordering::Greater,
        (LocalSegment::Str(_), LocalSegment::Numeric(_)) => Ordering::Less,
    }
}

impl PartialEq for Pep440Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Pep440Version {}

impl PartialOrd for Pep440Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Pep440Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let ord = self.epoch.cmp(&other.epoch);
        if ord != Ordering::Equal {
            return ord;
        }
        let ta = Pep440Version::trimmed_release(&self.release);
        let tb = Pep440Version::trimmed_release(&other.release);
        let len = ta.len().min(tb.len());
        for i in 0..len {
            let o = ta[i].cmp(&tb[i]);
            if o != Ordering::Equal {
                return o;
            }
        }
        let o = ta.len().cmp(&tb.len());
        if o != Ordering::Equal {
            return o;
        }
        let o = self.suffix().cmp(&other.suffix());
        if o != Ordering::Equal {
            return o;
        }
        cmp_local_opt(&self.local, &other.local)
    }
}

impl VersionInfo for Pep440Version {
    fn parse(raw: &str) -> Result<Self, BluelineError> {
        let err = |msg: &str| {
            BluelineError::InvalidPackageSpec(format!("`{raw}`: invalid PEP 440 version: {msg}"))
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(err("empty version"));
        }
        let after_v = if trimmed.starts_with('v') || trimmed.starts_with('V') {
            &trimmed[1..]
        } else {
            trimmed
        };
        if after_v.is_empty() {
            return Err(err("empty after leading v"));
        }
        if after_v.trim().len() != after_v.len() {
            return Err(err("whitespace after v"));
        }
        let lower = after_v.to_ascii_lowercase();
        let s = lower.as_str();

        if s.trim().len() != s.len() {
            return Err(err("whitespace"));
        }
        if s.is_empty() {
            return Err(err("empty"));
        }

        let (epoch, rest) = if let Some(idx) = s.find('!') {
            let epoch_str = &s[..idx];
            let rest = &s[idx + 1..];
            if epoch_str.is_empty() {
                return Err(err("empty epoch"));
            }
            if !epoch_str.chars().all(|c| c.is_ascii_digit()) {
                return Err(err("epoch must be digits"));
            }
            if s[idx + 1..].contains('!') {
                return Err(err("multiple !"));
            }
            if rest.is_empty() {
                return Err(err("empty after epoch"));
            }
            let epoch = epoch_str
                .parse::<u64>()
                .map_err(|_| err("epoch overflow"))?;
            (epoch, rest)
        } else {
            (0, s)
        };

        let (before_plus, local_str_opt) = if let Some(idx) = rest.find('+') {
            let before = &rest[..idx];
            let local = &rest[idx + 1..];
            if before.is_empty() {
                return Err(err("empty public before +"));
            }
            if local.is_empty() {
                return Err(err("empty local"));
            }
            if local.contains('+') {
                return Err(err("multiple +"));
            }
            if before.contains('+') {
                return Err(err("multiple +"));
            }
            (before, Some(local))
        } else {
            (rest, None)
        };

        let local = if let Some(ls) = local_str_opt {
            if !ls
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
            {
                return Err(err("invalid local chars"));
            }
            if ls.starts_with('.') || ls.starts_with('_') || ls.starts_with('-') {
                return Err(err("local starts with separator"));
            }
            if ls.ends_with('.') || ls.ends_with('_') || ls.ends_with('-') {
                return Err(err("local ends with separator"));
            }
            let bytes = ls.as_bytes();
            for i in 0..bytes.len().saturating_sub(1) {
                let a = bytes[i];
                let b = bytes[i + 1];
                let a_sep = a == b'.' || a == b'_' || a == b'-';
                let b_sep = b == b'.' || b == b'_' || b == b'-';
                if a_sep && b_sep {
                    return Err(err("consecutive separators in local"));
                }
            }
            let parts: Vec<&str> = ls.split(['.', '_', '-']).collect();
            let mut segs = Vec::with_capacity(parts.len());
            for p in parts {
                if p.is_empty() {
                    return Err(err("empty local segment"));
                }
                if p.chars().all(|c| c.is_ascii_digit()) {
                    let n = p
                        .parse::<u64>()
                        .map_err(|_| err("local numeric overflow"))?;
                    segs.push(LocalSegment::Numeric(n));
                } else {
                    if !p.chars().all(|c| c.is_ascii_alphanumeric()) {
                        return Err(err("invalid local segment"));
                    }
                    segs.push(LocalSegment::Str(p.to_string()));
                }
            }
            Some(segs)
        } else {
            None
        };

        let p = before_plus;
        if p.is_empty() {
            return Err(err("empty public version"));
        }
        let pb = p.as_bytes();
        let mut end = 0usize;
        while end < pb.len() && pb[end].is_ascii_digit() {
            end += 1;
        }
        if end == 0 {
            return Err(err("release must start with digit"));
        }
        loop {
            if end < pb.len() && pb[end] == b'.' {
                if end + 1 < pb.len() && pb[end + 1].is_ascii_digit() {
                    end += 1;
                    while end < pb.len() && pb[end].is_ascii_digit() {
                        end += 1;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        let release_str = &p[..end];
        let mut remaining = &p[end..];

        if release_str.starts_with('.') || release_str.ends_with('.') {
            return Err(err("release starts/ends with dot"));
        }
        if release_str.contains("..") {
            return Err(err("empty release segment"));
        }
        let rel_parts: Vec<&str> = release_str.split('.').collect();
        if rel_parts.iter().any(|x| x.is_empty()) {
            return Err(err("empty release segment"));
        }
        let mut release = Vec::with_capacity(rel_parts.len());
        for part in rel_parts {
            if !part.chars().all(|c| c.is_ascii_digit()) {
                return Err(err("release non-digit"));
            }
            let n = part.parse::<u64>().map_err(|_| err("release overflow"))?;
            release.push(n);
        }
        if release.is_empty() {
            return Err(err("empty release"));
        }

        let mut pre: Option<(PreKind, u64)> = None;
        let mut post: Option<u64> = None;
        let mut dev: Option<u64> = None;

        const PRE_LABELS: &[(&str, PreKind)] = &[
            ("preview", PreKind::Rc),
            ("alpha", PreKind::A),
            ("beta", PreKind::B),
            ("pre", PreKind::Rc),
            ("rc", PreKind::Rc),
            ("a", PreKind::A),
            ("b", PreKind::B),
            ("c", PreKind::Rc),
        ];
        const POST_LABELS: &[(&str, PreKind)] =
            &[("post", PreKind::A), ("rev", PreKind::A), ("r", PreKind::A)];
        const DEV_LABELS: &[(&str, PreKind)] = &[("dev", PreKind::A)];

        if let Some((consumed, kind, n)) = parse_suffix_label(remaining, PRE_LABELS) {
            pre = Some((kind, n));
            remaining = &remaining[consumed..];
        }
        if remaining.starts_with('-')
            && remaining.len() > 1
            && remaining.as_bytes()[1].is_ascii_digit()
        {
            let mut end = 1;
            while end < remaining.len() && remaining.as_bytes()[end].is_ascii_digit() {
                end += 1;
            }
            let n = remaining[1..end]
                .parse::<u64>()
                .map_err(|_| err("post overflow"))?;
            post = Some(n);
            remaining = &remaining[end..];
        } else if let Some((consumed, _, n)) = parse_suffix_label(remaining, POST_LABELS) {
            post = Some(n);
            remaining = &remaining[consumed..];
        }
        if let Some((consumed, _, n)) = parse_suffix_label(remaining, DEV_LABELS) {
            dev = Some(n);
            remaining = &remaining[consumed..];
        }

        if !remaining.is_empty() {
            return Err(err("trailing data"));
        }

        Ok(Pep440Version {
            epoch,
            release,
            pre,
            post,
            dev,
            local,
        })
    }

    fn canonical(&self) -> String {
        let mut out = String::new();
        if self.epoch != 0 {
            out.push_str(&self.epoch.to_string());
            out.push('!');
        }
        out.push_str(
            &self
                .release
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join("."),
        );
        if let Some((k, n)) = &self.pre {
            let label = match k {
                PreKind::A => "a",
                PreKind::B => "b",
                PreKind::Rc => "rc",
            };
            out.push_str(label);
            out.push_str(&n.to_string());
        }
        if let Some(n) = self.post {
            out.push_str(".post");
            out.push_str(&n.to_string());
        }
        if let Some(n) = self.dev {
            out.push_str(".dev");
            out.push_str(&n.to_string());
        }
        if let Some(segs) = &self.local {
            out.push('+');
            let parts: Vec<String> = segs
                .iter()
                .map(|s| match s {
                    LocalSegment::Numeric(n) => n.to_string(),
                    LocalSegment::Str(st) => st.clone(),
                })
                .collect();
            out.push_str(&parts.join("."));
        }
        out
    }

    fn is_prerelease(&self) -> bool {
        self.pre.is_some() || self.dev.is_some()
    }
}

fn parse_suffix_label(s: &str, labels: &[(&str, PreKind)]) -> Option<(usize, PreKind, u64)> {
    if s.is_empty() {
        return None;
    }
    let b = s.as_bytes();
    let mut sep = 0;
    if b[0] == b'.' || b[0] == b'_' || b[0] == b'-' {
        if s.len() == 1 {
            return None;
        }
        sep = 1;
    }
    let cand = &s[sep..];
    let (lab, kind) = labels.iter().find(|(lab, _)| cand.starts_with(*lab))?;
    let mut pos = sep + lab.len();
    if pos < s.len() && (b[pos] == b'.' || b[pos] == b'_' || b[pos] == b'-') {
        pos += 1;
    }
    let mut end = pos;
    while end < s.len() && b[end].is_ascii_digit() {
        end += 1;
    }
    let n = if pos == end {
        0
    } else {
        s[pos..end].parse::<u64>().ok()?
    };
    Some((end, kind.clone(), n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> semver::Version {
        <semver::Version as VersionInfo>::parse(s).unwrap()
    }

    fn pv(s: &str) -> Pep440Version {
        Pep440Version::parse(s).unwrap_or_else(|e| panic!("parse {s:?} failed: {e}"))
    }

    fn assert_version_eq(a: &str, b: &str, equal: bool) {
        let pa = pv(a);
        let pb = pv(b);
        if equal {
            assert_eq!(pa, pb, "{a} should equal {b}");
        } else {
            assert_ne!(pa, pb, "{a} should not equal {b}");
        }
    }

    #[test]
    fn parse_fails_closed_on_non_semver() {
        assert!(<semver::Version as VersionInfo>::parse("not-a-version").is_err());
        assert!(<semver::Version as VersionInfo>::parse("1.0").is_err());
        assert!(<semver::Version as VersionInfo>::parse("1.0.0").is_ok());
    }

    #[test]
    fn canonical_round_trips_semver() {
        let parsed = <semver::Version as VersionInfo>::parse("1.2.3-alpha.1+build").unwrap();
        assert_eq!(parsed.canonical(), "1.2.3-alpha.1+build");
    }

    #[test]
    fn prerelease_detection() {
        assert!(!v("1.0.0").is_prerelease());
        assert!(v("1.0.0-rc.1").is_prerelease());
    }

    #[test]
    fn baseline_eligibility_matches_baseline_rules() {
        assert!(v("1.9.0").baseline_eligible_for(&v("2.0.0")));
        assert!(!v("2.0.0").baseline_eligible_for(&v("2.0.0")));
        assert!(!v("2.1.0").baseline_eligible_for(&v("2.0.0")));
        assert!(!v("1.9.0-rc.1").baseline_eligible_for(&v("2.0.0")));
        assert!(v("1.9.0-rc.1").baseline_eligible_for(&v("2.0.0-beta.1")));
        assert!(v("1.9.0").baseline_eligible_for(&v("2.0.0-beta.1")));
    }

    #[test]
    fn pep440_versions_sorted_order() {
        let versions = vec![
            "1.0.dev0",
            "1.0.dev456",
            "1.0.dev456+local",
            "1.0a0",
            "1.0a0.post0.dev0",
            "1.0a0.post0",
            "1.0a1.dev1",
            "1.0a1.dev1+local",
            "1.0a1",
            "1.0a1+local",
            "1.0b0",
            "1.0b1.dev456",
            "1.0b2",
            "1.0b2.post345.dev456",
            "1.0b2.post345",
            "1.0b2-346",
            "1.0rc0",
            "1.0rc1.dev1",
            "1.0c1",
            "1.0rc2",
            "1.0",
            "1.0.post0.dev0",
            "1.0.post0",
            "1.0.post456.dev34",
            "1.0.post456",
            "1.0.post456+local",
            "1.0.1.dev1",
            "1.0.1a1",
            "1.0.1",
            "1.0.1+local",
            "1.0.1.post1",
            "1.1.dev1",
            "1.2+a",
            "1.2+abc",
            "1.2+abcdef",
            "1.2+def",
            "1.2+0",
            "1.2+1",
            "1.2+1.abc",
            "1.2+1.1",
            "1.2+1.1.0",
            "1.2+2",
            "1.2+123",
            "1.2+123456",
            "1.2.r32+123456",
            "1.2.rev33+123456",
            "1!1.0.dev0",
            "1!1.0.dev456",
            "1!1.0.dev456+local",
            "1!1.0a0",
            "1!1.0a0.post0.dev0",
            "1!1.0a0.post0",
            "1!1.0a1.dev1",
            "1!1.0a1.dev1+local",
            "1!1.0a1",
            "1!1.0a1+local",
            "1!1.0b0",
            "1!1.0b1.dev456",
            "1!1.0b2",
            "1!1.0b2.post345.dev456",
            "1!1.0b2.post345",
            "1!1.0b2-346",
            "1!1.0rc0",
            "1!1.0rc1.dev1",
            "1!1.0c1",
            "1!1.0rc2",
            "1!1.0",
            "1!1.0.post0.dev0",
            "1!1.0.post0",
            "1!1.0.post456.dev34",
            "1!1.0.post456",
            "1!1.0.post456+local",
            "1!1.0.1.dev1",
            "1!1.0.1a1",
            "1!1.0.1",
            "1!1.0.1+local",
            "1!1.0.1.post1",
            "1!1.1.dev1",
            "1!1.2+a",
            "1!1.2+abc",
            "1!1.2+abcdef",
            "1!1.2+def",
            "1!1.2+0",
            "1!1.2+1",
            "1!1.2+1.abc",
            "1!1.2+1.1",
            "1!1.2+1.1.0",
            "1!1.2+2",
            "1!1.2+123",
            "1!1.2+123456",
            "1!1.2.r32+123456",
            "1!1.2.rev33+123456",
        ];
        let parsed: Vec<Pep440Version> = versions.iter().map(|s| pv(s)).collect();
        for i in 0..parsed.len() {
            for j in i + 1..parsed.len() {
                assert!(
                    parsed[i] < parsed[j],
                    "{} should be < {} (idx {} < {})",
                    versions[i],
                    versions[j],
                    i,
                    j
                );
            }
        }
    }

    #[test]
    fn pep440_normalized_forms() {
        let cases = vec![
            ("1.0dev", "1.0.dev0"),
            ("1.0-dev1", "1.0.dev1"),
            ("1.0DEV", "1.0.dev0"),
            ("1.0a", "1.0a0"),
            ("1.0alpha", "1.0a0"),
            ("1.0A", "1.0a0"),
            ("1.0ALPHA1", "1.0a1"),
            ("1.0b", "1.0b0"),
            ("1.0beta1", "1.0b1"),
            ("1.0BETA", "1.0b0"),
            ("1.0c", "1.0rc0"),
            ("1.0.c1", "1.0rc1"),
            ("1.0rc", "1.0rc0"),
            ("1.0RC1", "1.0rc1"),
            ("1.0post", "1.0.post0"),
            ("1.0post1", "1.0.post1"),
            ("1.0r", "1.0.post0"),
            ("1.0rev", "1.0.post0"),
            ("1.0.r1", "1.0.post1"),
            ("1.0-5", "1.0.post5"),
            ("1.0-r5", "1.0.post5"),
            ("1.0-rev5", "1.0.post5"),
            ("1.0+AbC", "1.0+abc"),
            ("1.01", "1.1"),
            ("1.0a05", "1.0a5"),
            ("1.0c056", "1.0rc56"),
            ("1.0.post000", "1.0.post0"),
            ("1.1.dev09000", "1.1.dev9000"),
            ("00!1.2", "1.2"),
            ("v1.0", "1.0"),
            ("   v1.0\t\n", "1.0"),
        ];
        for (input, expected) in cases {
            let got = pv(input).canonical();
            assert_eq!(
                got, expected,
                "normalize {input:?} expected {expected:?} got {got:?}"
            );
        }
    }

    #[test]
    fn pep440_invalid_versions() {
        let invalid = vec![
            "french toast",
            "1.0+a+",
            "1.0++",
            "1.0+_foobar",
            "1.0+foo&asd",
            "1. 0",
            "1 .0",
            "1.0 a1",
            "٠١٢.٣٤٥.٦٧٨٩",
            ".",
            "..",
            "1..0",
            "1.0.",
            "1..2.3",
            "1.0+\u{0130}",
            "v",
            "",
            "   ",
            "1!",
            "!1.0",
            "1.0+",
            "1.0-",
            "1.0..",
        ];
        for s in invalid {
            assert!(Pep440Version::parse(s).is_err(), "expected invalid: {s:?}");
        }
    }

    #[test]
    fn pep440_release_zero_padding_equality() {
        assert_version_eq("1.0", "1.0.0", true);
        assert_version_eq("1.0.0.0", "1.0", true);
        assert!(pv("1.0") < pv("1.0.0.1"));
        assert!(pv("1.0") == pv("1.0.0"));
    }

    #[test]
    fn pep440_epoch_local_prerelease_ordering() {
        assert!(pv("1!1.0") > pv("2.0"));
        assert!(pv("1!1.0") > pv("1.0"));
        assert!(pv("0!1.0") == pv("1.0"));
        assert!(pv("1.0+abc.5") < pv("1.0+5"));
        assert!(pv("1.0.dev0") < pv("1.0a0"));
        assert!(pv("1.0a0") < pv("1.0b0"));
        assert!(pv("1.0b0") < pv("1.0rc0"));
        assert!(pv("1.0rc0") < pv("1.0"));
        assert!(pv("1.0") < pv("1.0.post1"));
    }

    #[test]
    fn pep440_is_prerelease() {
        assert!(pv("1.0.dev0").is_prerelease());
        assert!(pv("1.0a1").is_prerelease());
        assert!(pv("1.0b1").is_prerelease());
        assert!(pv("1.0rc1").is_prerelease());
        assert!(!pv("1.0").is_prerelease());
        assert!(!pv("1.0.post1").is_prerelease());
        assert!(!pv("1.0+local").is_prerelease());
    }

    #[test]
    fn pep440_baseline_eligible() {
        let stable = pv("1.9.0");
        let target = pv("2.0.0");
        assert!(stable.baseline_eligible_for(&target));
        let pre = pv("1.9.0a1");
        assert!(!pre.baseline_eligible_for(&target));
        let target_pre = pv("2.0.0a1");
        assert!(pre.baseline_eligible_for(&target_pre));
        assert!(stable.baseline_eligible_for(&target_pre));
    }

    #[test]
    fn pep503_canonicalize_name() {
        assert_eq!(canonicalize_name("Hello-World"), "hello-world");
        assert_eq!(canonicalize_name("hello__world"), "hello-world");
        assert_eq!(canonicalize_name("hello..world"), "hello-world");
        assert_eq!(canonicalize_name("Hello---World"), "hello-world");
        assert_eq!(
            canonicalize_name("hello_world.test-name"),
            "hello-world-test-name"
        );
        assert_eq!(canonicalize_name("Foo_Bar.Baz-Qux"), "foo-bar-baz-qux");
        assert_eq!(
            canonicalize_name(" already--normalized "),
            " already-normalized "
        );
    }

    #[test]
    fn pep503_validate_pypi_name() {
        assert!(validate_pypi_name("hello"));
        assert!(validate_pypi_name("hello-world"));
        assert!(validate_pypi_name("hello_world"));
        assert!(validate_pypi_name("hello.world"));
        assert!(validate_pypi_name("HELLOWORLD"));
        assert!(validate_pypi_name("a"));
        assert!(validate_pypi_name("a1"));
        assert!(!validate_pypi_name(""));
        assert!(!validate_pypi_name("-hello"));
        assert!(!validate_pypi_name("hello-"));
        assert!(!validate_pypi_name(".hello"));
        assert!(!validate_pypi_name("hello."));
        assert!(!validate_pypi_name("_hello"));
        assert!(!validate_pypi_name("hello!"));
        assert!(!validate_pypi_name("hello world"));
    }
}
