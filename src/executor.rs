use std::process::{Command, Stdio};

/// Executes `npm install --ignore-scripts <pkg> [extra_args...]`.
///
/// Delegates to `$npm_execpath` if set (e.g. when invoked through `npm` or `npx`),
/// otherwise defaults to `npm` on PATH.
pub fn install_with_ignore_scripts(pkg: &str, extra_args: &[String]) -> anyhow::Result<()> {
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

    cmd.arg("install")
        .arg("--ignore-scripts")
        .arg(pkg.trim())
        .args(extra_args)
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

pub fn validate_extra_args(extra_args: &[String]) -> anyhow::Result<()> {
    let mut iter = extra_args.iter().peekable();
    while let Some(arg) = iter.next() {
        let trimmed = arg.trim();
        if is_forbidden_flag(trimmed) {
            anyhow::bail!("forbidden flag `{trimmed}`: cannot override script isolation");
        }
        if trimmed == "--ignore-scripts" {
            let next_is_negation = iter.peek().is_some_and(|next| {
                let next_lower = next.trim().to_ascii_lowercase();
                matches!(next_lower.as_str(), "false" | "0" | "no" | "off")
            });
            if next_is_negation {
                anyhow::bail!(
                    "forbidden flag `--ignore-scripts`: cannot override script isolation"
                );
            }
        }
    }
    Ok(())
}

fn is_forbidden_flag(arg: &str) -> bool {
    let lower = arg.to_ascii_lowercase();
    lower == "--no-ignore-scripts"
        || lower.starts_with("--no-ignore-scripts=")
        || lower == "--ignore-scripts=false"
        || lower.starts_with("--ignore-scripts=false")
        || lower.starts_with("--ignore-scripts=0")
        || lower.starts_with("--ignore-scripts=no")
        || lower.starts_with("--ignore-scripts=off")
        || lower == "--foreground-scripts"
        || lower.starts_with("--foreground-scripts=")
        || lower == "--script-shell"
        || lower.starts_with("--script-shell=")
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
        ];
        assert!(validate_extra_args(&args).is_ok());
    }

    #[test]
    fn rejects_no_ignore_scripts() {
        let args = vec!["--no-ignore-scripts".to_string()];
        assert!(validate_extra_args(&args).is_err());
    }

    #[test]
    fn rejects_ignore_scripts_false() {
        let args = vec!["--ignore-scripts=false".to_string()];
        assert!(validate_extra_args(&args).is_err());

        let args2 = vec!["--ignore-scripts".to_string(), "false".to_string()];
        assert!(validate_extra_args(&args2).is_err());
    }

    #[test]
    fn rejects_foreground_scripts() {
        let args = vec!["--foreground-scripts".to_string()];
        assert!(validate_extra_args(&args).is_err());

        let args2 = vec!["--foreground-scripts=true".to_string()];
        assert!(validate_extra_args(&args2).is_err());
    }

    #[test]
    fn rejects_script_shell() {
        let args = vec!["--script-shell".to_string(), "/bin/sh".to_string()];
        assert!(validate_extra_args(&args).is_err());

        let args2 = vec!["--script-shell=/bin/sh".to_string()];
        assert!(validate_extra_args(&args2).is_err());
    }
}
