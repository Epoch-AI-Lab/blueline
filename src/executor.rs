use std::process::{Command, Stdio};

/// Executes `npm install --ignore-scripts --registry <registry> [extra_args...] -- <pkg>`.
///
/// Delegates to `$npm_execpath` if set (e.g. when invoked through `npm` or `npx`),
/// otherwise defaults to `npm` on PATH.
pub fn install_with_ignore_scripts(
    pkg: &str,
    registry_base: &str,
    extra_args: &[String],
) -> anyhow::Result<()> {
    validate_extra_args(extra_args)?;

    let mut cmd = match std::env::var("npm_execpath") {
        Ok(execpath) if !execpath.is_empty() => {
            if execpath.ends_with(".js") || execpath.ends_with(".cjs") || execpath.ends_with(".mjs")
            {
                let node_bin = std::env::var("NODE").unwrap_or_else(|_| "node".to_string());
                let mut c = Command::new(node_bin);
                c.arg(execpath);
                c
            } else {
                Command::new(execpath)
            }
        }
        _ => Command::new("npm"),
    };

    // Scrub sensitive environment variables to enforce script isolation.
    // Iterating over std::env::vars() ensures mixed-case keys (e.g. Npm_Config_*) are stripped on Unix.
    for (key, _) in std::env::vars() {
        let lower = key.to_ascii_lowercase();
        if lower.starts_with("npm_config_")
            || lower == "node_options"
            || lower == "node_extra_ca_certs"
        {
            cmd.env_remove(&key);
        }
    }

    cmd.arg("install")
        .arg("--ignore-scripts")
        .arg("--registry")
        .arg(registry_base)
        .args(extra_args)
        .arg("--")
        .arg(pkg.trim())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("failed to execute npm install: {e}"))?;

    if !status.success() {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(code) = status.code() {
                std::process::exit(code);
            } else if let Some(sig) = status.signal() {
                std::process::exit(128 + sig);
            } else {
                std::process::exit(1);
            }
        }
        #[cfg(not(unix))]
        {
            let code = status.code().unwrap_or(1);
            std::process::exit(code);
        }
    }

    Ok(())
}

fn normalize_key(arg: &str) -> String {
    arg.trim_start_matches('-')
        .chars()
        .filter(|&c| c != '-' && c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

pub fn validate_extra_args(extra_args: &[String]) -> anyhow::Result<()> {
    for arg in extra_args {
        let trimmed = arg.trim();
        if !trimmed.starts_with('-') {
            anyhow::bail!(
                "forbidden positional argument `{trimmed}`: extra arguments can only be npm CLI flags"
            );
        }

        let (raw_key, _) = trimmed.split_once('=').unwrap_or((trimmed, ""));
        let key = normalize_key(raw_key);

        // Disallow configuration, proxy, TLS, loader, auth and shell injection flags
        if matches!(
            key.as_str(),
            "userconfig"
                | "globalconfig"
                | "config"
                | "prefix"
                | "nodeoptions"
                | "loader"
                | "experimentalloader"
                | "import"
                | "scriptshell"
                | "shell"
                | "onloadscript"
                | "scriptsprependnodepath"
                | "registry"
                | "proxy"
                | "httpsproxy"
                | "httpproxy"
                | "noproxy"
                | "strictssl"
                | "nostrictssl"
                | "ca"
                | "cafile"
                | "cert"
                | "key"
                | "extracacerts"
                | "extracacert"
                | "initmodule"
                | "auth"
                | "authtoken"
        ) {
            anyhow::bail!(
                "forbidden flag `{trimmed}`: cannot override network, security or configuration options"
            );
        }

        if matches!(
            key.as_str(),
            "noignorescripts" | "ignorescripts" | "foregroundscripts"
        ) {
            anyhow::bail!("forbidden flag `{trimmed}`: cannot override script isolation");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_extra_args() {
        let args = vec![
            "--save-dev".to_string(),
            "--legacy-peer-deps".to_string(),
            "--verbose".to_string(),
            "--dry-run".to_string(),
        ];
        assert!(validate_extra_args(&args).is_ok());
    }

    #[test]
    fn rejects_no_ignore_scripts() {
        let variations = [
            "--no-ignore-scripts",
            "--no_ignore_scripts",
            "-no-ignore-scripts",
            "--no-ignore-scripts=true",
        ];
        for flag in variations {
            assert!(
                validate_extra_args(&[flag.to_string()]).is_err(),
                "should reject {flag}"
            );
        }
    }

    #[test]
    fn rejects_ignore_scripts_false() {
        let variations = [
            vec!["--ignore-scripts=false"],
            vec!["--ignore_scripts=false"],
            vec!["--ignoreScripts=false"],
            vec!["--ignore-scripts=0"],
            vec!["--ignore-scripts=no"],
            vec!["--ignore-scripts=off"],
            vec!["--ignore-scripts", "false"],
            vec!["--ignore_scripts", "0"],
            vec!["--ignoreScripts", "no"],
        ];
        for args in variations {
            let string_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            assert!(
                validate_extra_args(&string_args).is_err(),
                "should reject {:?}",
                args
            );
        }
    }

    #[test]
    fn rejects_foreground_scripts() {
        let variations = [
            vec!["--foreground-scripts"],
            vec!["--foreground_scripts"],
            vec!["--foregroundScripts"],
            vec!["--foreground-scripts=true"],
            vec!["--foreground_scripts=1"],
            vec!["--foreground-scripts", "true"],
        ];
        for args in variations {
            let string_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            assert!(
                validate_extra_args(&string_args).is_err(),
                "should reject {:?}",
                args
            );
        }
    }

    #[test]
    fn rejects_script_shell() {
        let variations = [
            vec!["--script-shell", "/bin/sh"],
            vec!["--script_shell", "/bin/sh"],
            vec!["--scriptShell", "/bin/sh"],
            vec!["--script-shell=/bin/sh"],
            vec!["--script_shell=/bin/sh"],
            vec!["--shell=/bin/sh"],
        ];
        for args in variations {
            let string_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            assert!(
                validate_extra_args(&string_args).is_err(),
                "should reject {:?}",
                args
            );
        }
    }

    #[test]
    fn rejects_positional_arguments() {
        let bad_args = [
            vec!["express@4.21.2".to_string()],
            vec!["--save-dev".to_string(), "malicious-pkg".to_string()],
            vec!["http://evil.com/payload.tgz".to_string()],
        ];
        for args in bad_args {
            assert!(
                validate_extra_args(&args).is_err(),
                "should reject positional package args: {:?}",
                args
            );
        }
    }

    #[test]
    fn rejects_network_and_ssl_override_flags() {
        let variations = [
            vec!["--proxy=http://10.0.0.1:8080"],
            vec!["--https-proxy=http://10.0.0.1:8080"],
            vec!["--http-proxy=http://10.0.0.1:8080"],
            vec!["--strict-ssl=false"],
            vec!["--no-strict-ssl"],
            vec!["--ca=/tmp/bad.crt"],
            vec!["--cafile=/tmp/bad.crt"],
            vec!["--cert=/tmp/bad.crt"],
            vec!["--key=/tmp/bad.key"],
            vec!["--registry=https://evil-registry.org"],
        ];
        for args in variations {
            let string_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            assert!(
                validate_extra_args(&string_args).is_err(),
                "should reject {:?}",
                args
            );
        }
    }

    #[test]
    fn rejects_config_and_node_options_injection() {
        let variations = [
            vec!["--userconfig=/tmp/bad.npmrc"],
            vec!["--user-config=/tmp/bad.npmrc"],
            vec!["--user_config=/tmp/bad.npmrc"],
            vec!["--globalconfig=/tmp/bad.npmrc"],
            vec!["--global-config=/tmp/bad.npmrc"],
            vec!["--global_config=/tmp/bad.npmrc"],
            vec!["--ca-file=/tmp/bad.crt"],
            vec!["--ca_file=/tmp/bad.crt"],
            vec!["--config=/tmp/bad.npmrc"],
            vec!["--prefix=/tmp/bad"],
            vec!["--node-options=--require /tmp/pwn.js"],
            vec!["--node_options=--require /tmp/pwn.js"],
            vec!["--nodeOptions", "--require /tmp/pwn.js"],
            vec!["--onload-script=/tmp/pwn.js"],
            vec!["--onload_script=/tmp/pwn.js"],
            vec!["--onloadscript", "/tmp/pwn.js"],
            vec!["--scripts-prepend-node-path"],
            vec!["--scripts_prepend_node_path"],
            vec!["--init-module=/tmp/pwn.js"],
            vec!["--auth=token"],
            vec!["--authtoken=token"],
        ];
        for args in variations {
            let string_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            assert!(
                validate_extra_args(&string_args).is_err(),
                "should reject {:?}",
                args
            );
        }
    }

    mod proptest_invariants {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig {
                failure_persistence: None,
                cases: 64,
                ..ProptestConfig::default()
            })]

            #[test]
            fn rejects_all_ignore_scripts_false_permutations(
                dashes in "[-]{1,3}",
                sep in "[-_]",
                val in "false|0|no|off",
                delimiter in "[= ]",
                extra_ws in "[ ]{0,2}"
            ) {
                let flag_str = format!("{extra_ws}{dashes}ignore{sep}scripts{delimiter}{val}{extra_ws}");
                let args = if delimiter == " " {
                    vec![
                        format!("{dashes}ignore{sep}scripts"),
                        val.to_string()
                    ]
                } else {
                    vec![flag_str]
                };
                prop_assert!(validate_extra_args(&args).is_err());
            }

            #[test]
            fn rejects_all_forbidden_flag_variations(
                dashes in "[-]{1,3}",
                flag in "userconfig|globalconfig|config|prefix|node-options|node_options|loader|experimental-loader|import|script-shell|script_shell|foreground-scripts|foreground_scripts",
                suffix in "(=[^ ]*| /[^ ]*)?"
            ) {
                let arg = format!("{dashes}{flag}{suffix}");
                let args = if suffix.starts_with(' ') {
                    let parts: Vec<String> = arg.split_whitespace().map(|s| s.to_string()).collect();
                    parts
                } else {
                    vec![arg]
                };
                prop_assert!(validate_extra_args(&args).is_err());
            }
        }
    }
}
