use std::collections::HashMap;

use crate::error::BluelineError;
use crate::verdict::VerdictBand;

pub const PKGBUILD_MAX_BYTES: usize = 1_048_576;
pub const PKGBUILD_MAX_LINES: usize = 64_000;
const MAX_ASSIGNMENTS: usize = 4096;
const MAX_ARRAY_ELEMENTS: usize = 4096;
const MAX_FOLDED_BYTES: usize = 65_536;
const MAX_FOLD_PASSES: usize = 8;
const MAX_NESTING_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub enum FoldedValue {
    Known(String),
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct FoldedPkgbuild {
    pub scalars: HashMap<String, FoldedValue>,
    pub arrays: HashMap<String, Vec<FoldedValue>>,
    pub func_bodies: HashMap<String, String>,
    pub suspicious_unicode: bool,
    pub meta_subst_arrays: Vec<String>,
    pub has_indirection: bool,
    pub assoc: HashMap<String, Vec<FoldedValue>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PkgFinding {
    pub rule_id: String,
    pub severity: VerdictBand,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq)]
enum WordPart {
    Literal(String),
    VarRef(String),
    Tainted,
}

fn pkgbuild_err(msg: String) -> BluelineError {
    BluelineError::Manifest("PKGBUILD".to_string(), msg)
}

pub fn contains_suspicious_unicode(text: &str) -> bool {
    for ch in text.chars() {
        let cp = ch as u32;
        let suspicious = matches!(
            cp,
            0x00AD
                | 0x180E
                | 0x200B
                | 0x200C
                | 0x200D
                | 0x200E
                | 0x200F
                | 0x202A
                | 0x202B
                | 0x202C
                | 0x202D
                | 0x202E
                | 0x2060
                | 0x2066
                | 0x2067
                | 0x2068
                | 0x2069
                | 0xFEFF
        );
        if suspicious {
            return true;
        }
    }
    false
}

fn is_name_char(ch: char, first: bool) -> bool {
    ch.is_ascii_alphabetic() || ch == '_' || (!first && ch.is_ascii_digit())
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if is_name_char(first, true) => chars.all(|c| is_name_char(c, false)),
        _ => false,
    }
}

fn decode_ansi_c(body: &str) -> Result<String, BluelineError> {
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let esc = chars
            .next()
            .ok_or_else(|| pkgbuild_err("dangling backslash in $'...' literal".to_string()))?;
        match esc {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            'f' => out.push('\x0C'),
            'v' => out.push('\x0B'),
            '\\' => out.push('\\'),
            '\'' => out.push('\''),
            '"' => out.push('"'),
            'e' | 'E' => out.push('\x1B'),
            'x' => {
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() != 2 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(pkgbuild_err(format!("bad \\x escape in $'...': `{hex}`")));
                }
                let byte = u8::from_str_radix(&hex, 16)
                    .map_err(|_| pkgbuild_err("bad hex".to_string()))?;
                out.push(byte as char);
            }
            'u' => {
                let hex: String = chars.by_ref().take(4).collect();
                if hex.len() != 4 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(pkgbuild_err(format!("bad \\u escape in $'...': `{hex}`")));
                }
                let cp = u32::from_str_radix(&hex, 16)
                    .map_err(|_| pkgbuild_err("bad unicode".to_string()))?;
                out.push(
                    char::from_u32(cp)
                        .ok_or_else(|| pkgbuild_err("bad unicode scalar".to_string()))?,
                );
            }
            '0'..='7' => {
                let mut oct = String::from(esc);
                for _ in 0..2 {
                    match chars.clone().next() {
                        Some(next) if matches!(next, '0'..='7') => {
                            oct.push(next);
                            chars.next();
                        }
                        _ => break,
                    }
                }
                let cp = u32::from_str_radix(&oct, 8)
                    .map_err(|_| pkgbuild_err("bad octal".to_string()))?;
                out.push(
                    char::from_u32(cp)
                        .ok_or_else(|| pkgbuild_err("bad octal scalar".to_string()))?,
                );
            }
            other => {
                return Err(pkgbuild_err(format!(
                    "unknown escape `\\{other}` in $'...' literal"
                )));
            }
        }
    }
    Ok(out)
}

fn find_matching(input: &str, start: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for (idx, ch) in input.char_indices().skip_while(|(i, _)| *i < start) {
        let _ = idx;
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && !in_single {
            escaped = true;
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        if in_double {
            if ch == '"' {
                in_double = false;
            }
            continue;
        }
        if ch == '\'' {
            in_single = true;
            continue;
        }
        if ch == '"' {
            in_double = true;
            continue;
        }
        if ch == open {
            depth += 1;
        } else if ch == close {
            if depth == 0 {
                return None;
            }
            depth -= 1;
            if depth == 0 {
                return Some(idx);
            }
        }
    }
    None
}

fn split_words(input: &str) -> Result<Vec<WordPart>, BluelineError> {
    let mut parts = Vec::new();
    let mut literal = String::new();
    let flush = |literal: &mut String, parts: &mut Vec<WordPart>| {
        if !literal.is_empty() {
            parts.push(WordPart::Literal(std::mem::take(literal)));
        }
    };
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '\'' {
            let mut j = i + 1;
            let mut body = String::new();
            let mut closed = false;
            while j < chars.len() {
                if chars[j] == '\'' {
                    closed = true;
                    break;
                }
                body.push(chars[j]);
                j += 1;
            }
            if !closed {
                return Err(pkgbuild_err("unterminated single quote".to_string()));
            }
            literal.push_str(&body);
            i = j + 1;
        } else if ch == '"' {
            i += 1;
            let mut closed = false;
            while i < chars.len() {
                let inner = chars[i];
                if inner == '"' {
                    closed = true;
                    i += 1;
                    break;
                }
                if inner == '\\'
                    && i + 1 < chars.len()
                    && matches!(chars[i + 1], '$' | '`' | '"' | '\\' | '\n')
                {
                    i += 1;
                    if chars[i] != '\n' {
                        literal.push(chars[i]);
                    }
                    i += 1;
                    continue;
                }
                if inner == '$' {
                    flush(&mut literal, &mut parts);
                    i = parse_dollar(&chars, i, &mut parts)?;
                    continue;
                }
                if inner == '`' {
                    flush(&mut literal, &mut parts);
                    parts.push(WordPart::Tainted);
                    i = skip_backtick(&chars, i)?;
                    continue;
                }
                literal.push(inner);
                i += 1;
            }
            if !closed {
                return Err(pkgbuild_err("unterminated double quote".to_string()));
            }
        } else if ch == '$' && i + 1 < chars.len() && chars[i + 1] == '\'' {
            let rest: String = chars[i + 2..].iter().collect();
            let mut body = String::new();
            let mut k = 0;
            let rest_chars: Vec<char> = rest.chars().collect();
            let mut closed = false;
            while k < rest_chars.len() {
                if rest_chars[k] == '\\' && k + 1 < rest_chars.len() {
                    body.push('\\');
                    body.push(rest_chars[k + 1]);
                    k += 2;
                    continue;
                }
                if rest_chars[k] == '\'' {
                    closed = true;
                    break;
                }
                body.push(rest_chars[k]);
                k += 1;
            }
            if !closed {
                return Err(pkgbuild_err("unterminated $'...' literal".to_string()));
            }
            literal.push_str(&decode_ansi_c(&body)?);
            i += 2 + k + 1;
        } else if ch == '$' && i + 1 < chars.len() && chars[i + 1] == '"' {
            flush(&mut literal, &mut parts);
            parts.push(WordPart::Tainted);
            i = skip_quoted(&chars, i + 1, '"')?;
        } else if ch == '$' {
            flush(&mut literal, &mut parts);
            i = parse_dollar(&chars, i, &mut parts)?;
        } else if ch == '`' {
            flush(&mut literal, &mut parts);
            parts.push(WordPart::Tainted);
            i = skip_backtick(&chars, i)?;
        } else if ch == '\\' && i + 1 < chars.len() {
            literal.push(chars[i + 1]);
            i += 2;
        } else {
            literal.push(ch);
            i += 1;
        }
    }
    flush(&mut literal, &mut parts);
    Ok(parts)
}

fn skip_backtick(chars: &[char], start: usize) -> Result<usize, BluelineError> {
    let mut i = start + 1;
    while i < chars.len() {
        if chars[i] == '\\' {
            i += 2;
            continue;
        }
        if chars[i] == '`' {
            return Ok(i + 1);
        }
        i += 1;
    }
    Err(pkgbuild_err(
        "unterminated backtick substitution".to_string(),
    ))
}

fn skip_quoted(chars: &[char], start: usize, quote: char) -> Result<usize, BluelineError> {
    let mut i = start + 1;
    while i < chars.len() {
        if chars[i] == '\\' {
            i += 2;
            continue;
        }
        if chars[i] == quote {
            return Ok(i + 1);
        }
        i += 1;
    }
    Err(pkgbuild_err("unterminated quoted string".to_string()))
}

fn parse_dollar(
    chars: &[char],
    start: usize,
    parts: &mut Vec<WordPart>,
) -> Result<usize, BluelineError> {
    let rest = &chars[start + 1..];
    if rest.is_empty() {
        parts.push(WordPart::Literal("$".to_string()));
        return Ok(start + 1);
    }
    match rest[0] {
        '(' => {
            if rest.len() > 1 && rest[1] == '(' {
                parts.push(WordPart::Tainted);
                skip_balanced(chars, start + 1, "$(( ".len(), "((", "))")
            } else {
                parts.push(WordPart::Tainted);
                skip_balanced(chars, start + 1, "$(".len(), "(", ")")
            }
        }
        '{' => {
            let end = find_brace_end(chars, start + 2)?;
            let body: String = chars[start + 2..end].iter().collect();
            if let Some(name) = plain_var_ref(&body) {
                parts.push(WordPart::VarRef(name));
            } else {
                parts.push(WordPart::Tainted);
            }
            Ok(end + 1)
        }
        '<' | '>' => {
            parts.push(WordPart::Tainted);
            Ok(start + 2)
        }
        ch if is_name_char(ch, true) => {
            let mut j = start + 1;
            while j < chars.len() && is_name_char(chars[j], false) {
                j += 1;
            }
            let name: String = chars[start + 1..j].iter().collect();
            parts.push(WordPart::VarRef(name));
            Ok(j)
        }
        '*' | '@' | '#' | '?' | '$' | '!' | '-' | '0'..='9' => {
            parts.push(WordPart::Tainted);
            Ok(start + 2)
        }
        _ => {
            parts.push(WordPart::Literal("$".to_string()));
            Ok(start + 1)
        }
    }
}

fn plain_var_ref(body: &str) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    if body.starts_with('!') {
        return None;
    }
    if body.contains([
        '/', ':', '-', '+', '=', '?', '#', '%', '^', ',', '@', '*', '[', ']', ' ',
    ]) {
        return None;
    }
    if valid_name(body) {
        return Some(body.to_string());
    }
    None
}

fn find_brace_end(chars: &[char], start: usize) -> Result<usize, BluelineError> {
    let mut depth = 1usize;
    let mut i = start;
    let mut nest = 0usize;
    while i < chars.len() {
        if nest > MAX_NESTING_DEPTH {
            return Err(pkgbuild_err("expansion nesting too deep".to_string()));
        }
        match chars[i] {
            '{' => {
                depth += 1;
                nest += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    Err(pkgbuild_err("unterminated ${...} expansion".to_string()))
}

fn skip_balanced(
    chars: &[char],
    dollar: usize,
    prefix_len: usize,
    open: &str,
    close: &str,
) -> Result<usize, BluelineError> {
    let open_chars: Vec<char> = open.chars().collect();
    let close_chars: Vec<char> = close.chars().collect();
    let tail: Vec<char> = chars[dollar..].to_vec();
    let mut depth = 0usize;
    let mut i = prefix_len;
    let mut steps = 0usize;
    while i < tail.len() {
        steps += 1;
        if steps > 4096 {
            return Err(pkgbuild_err("substitution too long".to_string()));
        }
        if tail[i..].starts_with(&open_chars) {
            depth += 1;
            i += open_chars.len();
            continue;
        }
        if tail[i..].starts_with(&close_chars) {
            if depth == 0 {
                return Ok(dollar + i + close_chars.len());
            }
            depth -= 1;
            i += close_chars.len();
            continue;
        }
        if depth == 0 && open == "(" && (tail[i] == '\'' || tail[i] == '"') {
            let quote = tail[i];
            let mut j = i + 1;
            let mut closed = false;
            while j < tail.len() {
                if tail[j] == '\\' {
                    j += 2;
                    continue;
                }
                if tail[j] == quote {
                    closed = true;
                    break;
                }
                j += 1;
            }
            if !closed {
                return Err(pkgbuild_err(
                    "unterminated quote in substitution".to_string(),
                ));
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    Err(pkgbuild_err(
        "unterminated command substitution".to_string(),
    ))
}

fn join_continuations(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut in_single = false;
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '\'' {
            in_single = !in_single;
            out.push(ch);
        } else if ch == '\\' && !in_single && i + 1 < chars.len() && chars[i + 1] == '\n' {
            i += 2;
            continue;
        } else {
            out.push(ch);
        }
        i += 1;
    }
    out
}

fn logical_complete(buf: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut depth = 0i64;
    for ch in buf.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && !in_single {
            escaped = true;
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        if in_double {
            if ch == '"' {
                in_double = false;
            }
            continue;
        }
        match ch {
            '\'' => in_single = true,
            '"' => in_double = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            _ => {}
        }
    }
    !in_single && !in_double && !escaped && depth == 0
}

fn strip_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut prev_boundary = true;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            prev_boundary = false;
            continue;
        }
        if ch == '\\' && !in_single {
            escaped = true;
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            prev_boundary = false;
            continue;
        }
        if in_double {
            if ch == '"' {
                in_double = false;
            }
            prev_boundary = false;
            continue;
        }
        if ch == '\'' {
            in_single = true;
            prev_boundary = false;
        } else if ch == '"' {
            in_double = true;
            prev_boundary = false;
        } else if ch == '#' && prev_boundary {
            return line[..idx].trim_end();
        } else {
            prev_boundary =
                ch.is_whitespace() || matches!(ch, ';' | '&' | '|' | '(' | '{' | ')' | '<' | '>');
        }
    }
    line
}

fn split_array_elements(body: &str) -> Result<Vec<String>, BluelineError> {
    let mut elements = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut depth_paren = 0usize;
    let mut depth_brace = 0usize;
    let body_chars: Vec<char> = body.chars().collect();
    for ch in body_chars {
        if escaped {
            current.push('\\');
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && !in_single {
            escaped = true;
            continue;
        }
        if in_single {
            current.push(ch);
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        if in_double {
            current.push(ch);
            if ch == '"' {
                in_double = false;
            }
            continue;
        }
        match ch {
            '\'' => {
                in_single = true;
                current.push(ch);
            }
            '"' => {
                in_double = true;
                current.push(ch);
            }
            '(' => {
                depth_paren += 1;
                current.push(ch);
            }
            ')' => {
                if depth_paren == 0 {
                    return Err(pkgbuild_err("unbalanced paren in array".to_string()));
                }
                depth_paren -= 1;
                current.push(ch);
            }
            '{' => {
                depth_brace += 1;
                current.push(ch);
            }
            '}' => {
                if depth_brace == 0 {
                    return Err(pkgbuild_err("unbalanced brace in array".to_string()));
                }
                depth_brace -= 1;
                current.push(ch);
            }
            c if c.is_whitespace() && depth_paren == 0 && depth_brace == 0 => {
                if !current.is_empty() {
                    elements.push(std::mem::take(&mut current));
                }
            }
            // A surviving `#` is mid-word (line comments were stripped per
            // line before joining), so it is an ordinary character.
            _ => current.push(ch),
        }
        if elements.len() > MAX_ARRAY_ELEMENTS {
            return Err(pkgbuild_err("array element cap exceeded".to_string()));
        }
    }
    if escaped {
        return Err(pkgbuild_err("dangling backslash in array".to_string()));
    }
    if in_single || in_double {
        return Err(pkgbuild_err("unterminated quote in array".to_string()));
    }
    if depth_paren != 0 || depth_brace != 0 {
        return Err(pkgbuild_err("unbalanced grouping in array".to_string()));
    }
    if !current.is_empty() {
        elements.push(current);
    }
    Ok(elements)
}

fn is_func_name_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '+' | ':' | '@' | '/')
}

/// Function head plus body opener. Accepts `name() {`, `name () {`,
/// `name() (`, `function name {`, `function name() {`. Split-package
/// `package_foo-bar()` names carry hyphens, so function names allow `-`
/// (variable names still do not). Returns the name and `{` or `(`.
fn func_head(line: &str) -> Option<(String, char)> {
    let trimmed = line.trim();
    let after_kw = match trimmed.strip_prefix("function") {
        Some(rest)
            if rest.is_empty()
                || rest.starts_with(char::is_whitespace)
                || rest.starts_with('-') =>
        {
            rest.trim_start()
        }
        Some(_) => return None,
        None => trimmed,
    };
    if after_kw.is_empty() {
        return None;
    }
    let name: String = after_kw
        .chars()
        .take_while(|c| is_func_name_char(*c))
        .collect();
    if name.is_empty() {
        return None;
    }
    let mut tail = after_kw[name.len()..].trim_start();
    if tail.starts_with('(') {
        let mut depth = 0usize;
        let mut end = None;
        for (idx, ch) in tail.char_indices() {
            if ch == '(' {
                depth += 1;
            } else if ch == ')' {
                depth -= 1;
                if depth == 0 {
                    end = Some(idx);
                    break;
                }
            }
        }
        tail = tail[end?..].trim_start_matches(')').trim_start();
    }
    match tail.chars().next() {
        Some('{') => Some((name, '{')),
        Some('(') => Some((name, '(')),
        _ => None,
    }
}

fn resolve_word(parts: &[WordPart], scalars: &HashMap<String, FoldedValue>) -> FoldedValue {
    let mut out = String::new();
    for part in parts {
        match part {
            WordPart::Literal(text) => out.push_str(text),
            WordPart::VarRef(name) => match scalars.get(name) {
                Some(FoldedValue::Known(value)) => out.push_str(value),
                _ => return FoldedValue::Unknown,
            },
            WordPart::Tainted => return FoldedValue::Unknown,
        }
        if out.len() > MAX_FOLDED_BYTES {
            return FoldedValue::Unknown;
        }
    }
    FoldedValue::Known(out)
}

pub fn parse_pkgbuild(input: &str) -> Result<FoldedPkgbuild, BluelineError> {
    if input.len() > PKGBUILD_MAX_BYTES {
        return Err(pkgbuild_err(format!(
            "PKGBUILD exceeds {} byte cap",
            PKGBUILD_MAX_BYTES
        )));
    }
    if input.lines().count() > PKGBUILD_MAX_LINES {
        return Err(pkgbuild_err(format!(
            "PKGBUILD exceeds {} line cap",
            PKGBUILD_MAX_LINES
        )));
    }
    let joined = join_continuations(input);
    let mut folded = FoldedPkgbuild {
        suspicious_unicode: contains_suspicious_unicode(input),
        has_indirection: false,
        ..FoldedPkgbuild::default()
    };
    let mut raw_scalars: HashMap<String, String> = HashMap::new();
    let mut raw_arrays: HashMap<String, Vec<String>> = HashMap::new();
    let mut assoc_raw: HashMap<String, Vec<String>> = HashMap::new();
    let mut assignment_count = 0usize;
    let mut ordered: Vec<RawAssign> = Vec::new();

    let lines: Vec<&str> = joined.lines().collect();
    let mut idx = 0;
    let mut top_shell = String::new();
    while idx < lines.len() {
        let line = lines[idx];
        let code = strip_comment(line);
        if code.trim().is_empty() {
            idx += 1;
            continue;
        }
        if let Some((name, opener)) = func_head(code) {
            let closer = if opener == '{' { '}' } else { ')' };
            let mut body = String::new();
            let mut depth = 0usize;
            let mut started = false;
            let mut in_single = false;
            let mut in_double = false;
            let mut escaped = false;
            let mut j = idx;
            while j < lines.len() {
                let text = lines[j];
                let mut k = 0;
                let text_chars: Vec<char> = text.chars().collect();
                while k < text_chars.len() {
                    let ch = text_chars[k];
                    if escaped {
                        escaped = false;
                        if started {
                            body.push(ch);
                        }
                        k += 1;
                        continue;
                    }
                    if ch == '\\' && !in_single {
                        escaped = true;
                        if started {
                            body.push(ch);
                        }
                        k += 1;
                        continue;
                    }
                    if in_single {
                        if started {
                            body.push(ch);
                        }
                        if ch == '\'' {
                            in_single = false;
                        }
                        k += 1;
                        continue;
                    }
                    if in_double {
                        if started {
                            body.push(ch);
                        }
                        if ch == '"' {
                            in_double = false;
                        }
                        k += 1;
                        continue;
                    }
                    if ch == '\'' {
                        in_single = true;
                    } else if ch == '"' {
                        in_double = true;
                    } else if ch == '#' {
                        if started {
                            body.push_str(&text_chars[k..].iter().collect::<String>());
                        }
                        break;
                    } else if ch == opener {
                        depth += 1;
                        started = true;
                    } else if ch == closer {
                        if depth == 0 {
                            return Err(pkgbuild_err(format!(
                                "unbalanced `{closer}` in function `{name}`"
                            )));
                        }
                        depth -= 1;
                    }
                    if started {
                        body.push(ch);
                    }
                    if started && depth == 0 {
                        break;
                    }
                    k += 1;
                }
                if started && depth == 0 {
                    break;
                }
                body.push('\n');
                j += 1;
                if j - idx > PKGBUILD_MAX_LINES {
                    return Err(pkgbuild_err("function body too long".to_string()));
                }
            }
            if !started {
                idx += 1;
                continue;
            }
            let scan: String = body
                .lines()
                .map(strip_comment)
                .collect::<Vec<_>>()
                .join("\n");
            folded.has_indirection |= has_true_indirection(&scan);
            folded.func_bodies.insert(name, body);
            idx = j + 1;
            continue;
        }
        let mut buffer = code.to_string();
        let mut end = idx;
        while !logical_complete(&buffer) && end + 1 < lines.len() {
            end += 1;
            if end - idx > 4096 {
                return Err(pkgbuild_err("assignment spans too many lines".to_string()));
            }
            buffer.push('\n');
            buffer.push_str(strip_comment(lines[end]));
        }
        if !logical_complete(&buffer) {
            return Err(pkgbuild_err("unterminated assignment".to_string()));
        }
        folded.has_indirection |= has_true_indirection(&buffer);
        if let Some(assign) = parse_assignment(&buffer)? {
            assignment_count += 1;
            if assignment_count > MAX_ASSIGNMENTS {
                return Err(pkgbuild_err("assignment cap exceeded".to_string()));
            }
            ordered.push(assign);
            idx = end + 1;
            continue;
        }
        // Not an assignment or function: top-level shell. `makepkg` sources
        // the file, so these lines execute. `export`/`local` prefixes still
        // carry assignments worth folding.
        let unprefixed = ["export ", "local ", "declare ", "typeset "]
            .iter()
            .find_map(|prefix| buffer.strip_prefix(prefix))
            .unwrap_or(&buffer);
        if let Some(assign) = parse_assignment(unprefixed)? {
            assignment_count += 1;
            if assignment_count > MAX_ASSIGNMENTS {
                return Err(pkgbuild_err("assignment cap exceeded".to_string()));
            }
            ordered.push(assign);
        } else if !buffer.trim().is_empty() {
            top_shell.push_str(buffer.trim());
            top_shell.push('\n');
        }
        idx = end + 1;
    }
    if !top_shell.trim().is_empty() {
        folded.func_bodies.insert("<top>".to_string(), top_shell);
    }
    for assign in ordered {
        match assign {
            RawAssign::Scalar {
                name,
                value,
                append,
            } => {
                if append {
                    let prev = raw_scalars.remove(&name).unwrap_or_default();
                    raw_scalars.insert(name, prev + &value);
                } else {
                    raw_scalars.insert(name, value);
                }
            }
            RawAssign::Array {
                name,
                values,
                append,
            } => {
                if values.len() > MAX_ARRAY_ELEMENTS {
                    return Err(pkgbuild_err(format!("array `{name}` exceeds element cap")));
                }
                if append {
                    raw_arrays.entry(name).or_default().extend(values);
                } else {
                    raw_arrays.insert(name, values);
                }
            }
            RawAssign::Indexed {
                name,
                idx,
                value,
                append,
            } => {
                if idx >= MAX_ARRAY_ELEMENTS {
                    return Err(pkgbuild_err(format!("array `{name}` index out of range")));
                }
                let entry = raw_arrays.entry(name.clone()).or_default();
                while entry.len() <= idx {
                    entry.push("$(__blueline_pad)".to_string());
                }
                if append {
                    entry[idx].push_str(&value);
                } else {
                    entry[idx] = value;
                }
            }
            RawAssign::Assoc { name, value } => {
                assoc_raw.entry(name).or_default().push(value);
            }
        }
    }

    for _ in 0..MAX_FOLD_PASSES {
        let mut changed = false;
        let snapshot = folded.scalars.clone();
        let mut working: HashMap<String, FoldedValue> = snapshot;
        for (name, raw) in &raw_scalars {
            if matches!(working.get(name), Some(FoldedValue::Known(_))) {
                continue;
            }
            let parts = split_words(raw)?;
            let value = resolve_word(&parts, &working);
            if matches!(value, FoldedValue::Known(_)) {
                working.insert(name.clone(), value);
                changed = true;
            }
        }
        folded.scalars = working;
        if !changed {
            break;
        }
    }
    for (name, raw) in &raw_scalars {
        if folded.scalars.contains_key(name) {
            continue;
        }
        let parts = split_words(raw).unwrap_or_default();
        let snapshot = folded.scalars.clone();
        let value = resolve_word(&parts, &snapshot);
        folded.scalars.insert(name.clone(), value);
    }
    for (name, raws) in &raw_arrays {
        let mut values = Vec::with_capacity(raws.len().min(MAX_ARRAY_ELEMENTS));
        for raw in raws {
            let (expanded, truncated) = expand_braces(raw);
            for text in expanded {
                if values.len() >= MAX_ARRAY_ELEMENTS {
                    return Err(pkgbuild_err(format!("array `{name}` exceeds element cap")));
                }
                let parts = split_words(&text)?;
                values.push(resolve_word(&parts, &folded.scalars));
            }
            if truncated {
                values.push(FoldedValue::Unknown);
            }
        }
        folded.arrays.insert(name.clone(), values);
    }
    for (name, raws) in &assoc_raw {
        let mut values = Vec::new();
        for raw in raws {
            let parts = split_words(raw)?;
            values.push(resolve_word(&parts, &folded.scalars));
        }
        folded.assoc.insert(name.clone(), values);
    }
    for (name, raws) in &raw_arrays {
        if array_is_meta(name)
            && raws
                .iter()
                .any(|raw| raw != "$(__blueline_pad)" && contains_cmd_subst(raw))
            && !folded.meta_subst_arrays.contains(name)
        {
            folded.meta_subst_arrays.push(name.clone());
        }
    }
    Ok(folded)
}

enum RawAssign {
    Scalar {
        name: String,
        value: String,
        append: bool,
    },
    Array {
        name: String,
        values: Vec<String>,
        append: bool,
    },
    Indexed {
        name: String,
        idx: usize,
        value: String,
        append: bool,
    },
    Assoc {
        name: String,
        value: String,
    },
}

fn parse_assignment(code: &str) -> Result<Option<RawAssign>, BluelineError> {
    let trimmed = code.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let bytes: Vec<char> = trimmed.chars().collect();
    let mut i = 0;
    while i < bytes.len() && is_name_char(bytes[i], i == 0) {
        i += 1;
    }
    if i == 0 {
        return Ok(None);
    }
    let name: String = bytes[..i].iter().collect();
    if !valid_name(&name) {
        return Ok(None);
    }
    let rest: String = bytes[i..].iter().collect();
    let rest = rest.trim_start();
    if rest.starts_with('[') {
        let close = rest.find(']').unwrap_or(usize::MAX);
        if close == usize::MAX {
            return Err(pkgbuild_err(format!("unbalanced index in `{name}`")));
        }
        let after = rest[close + 1..].trim_start();
        let (append, value) = if let Some(stripped) = after.strip_prefix("+=") {
            (true, stripped)
        } else if let Some(stripped) = after.strip_prefix('=') {
            (false, stripped)
        } else {
            // Not an assignment at all (`if [ ... ]`, `[ test ]`).
            return Ok(None);
        };
        let key = rest[1..close].trim();
        if let Ok(idx) = key.parse::<usize>() {
            return Ok(Some(RawAssign::Indexed {
                name,
                idx,
                value: value.trim().to_string(),
                append,
            }));
        }
        // Associative array write (`map[key]=value`). Rules never read
        // assoc storage, but the write must not crash the parse and the
        // value still folds for taint tracking.
        return Ok(Some(RawAssign::Assoc {
            name,
            value: value.trim().to_string(),
        }));
    }
    let (append, value) = if let Some(stripped) = rest.strip_prefix("+=") {
        (true, stripped)
    } else if let Some(stripped) = rest.strip_prefix('=') {
        (false, stripped)
    } else {
        return Ok(None);
    };
    let value = value.trim();
    if value.starts_with('(') {
        let end = find_matching(value, 0, '(', ')')
            .ok_or_else(|| pkgbuild_err(format!("unbalanced array in `{name}`")))?;
        let body = &value[1..end];
        let elements = split_array_elements(body)?;
        let tail = value[end + 1..].trim();
        if !tail.is_empty() && !tail.starts_with('#') {
            return Err(pkgbuild_err(format!("trailing text after array `{name}`")));
        }
        Ok(Some(RawAssign::Array {
            name,
            values: elements,
            append,
        }))
    } else {
        Ok(Some(RawAssign::Scalar {
            name,
            value: value.to_string(),
            append,
        }))
    }
}

fn quote_token_word(text: &str) -> String {
    if !text.is_empty()
        && text.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b':' | b'+' | b'@')
        })
    {
        text.to_string()
    } else {
        let mut out = String::from("\"");
        for ch in text.chars() {
            if matches!(ch, '\\' | '"' | '$' | '`') {
                out.push('\\');
            }
            out.push(ch);
        }
        out.push('"');
        out
    }
}

pub fn tokenize(input: &str) -> Result<Vec<String>, BluelineError> {
    let folded = parse_pkgbuild(input)?;
    let mut tokens = Vec::new();
    for (name, value) in &folded.scalars {
        match value {
            FoldedValue::Known(text) => tokens.push(format!("{name}={}", quote_token_word(text))),
            FoldedValue::Unknown => tokens.push(format!("{name}=<unknown>")),
        }
    }
    for (name, values) in &folded.arrays {
        let rendered: Vec<String> = values
            .iter()
            .map(|value| match value {
                FoldedValue::Known(text) => quote_token_word(text),
                FoldedValue::Unknown => "<unknown>".to_string(),
            })
            .collect();
        tokens.push(format!("{name}=({})", rendered.join(" ")));
    }
    Ok(tokens)
}

pub fn resolve_vars(tokens: &[String]) -> Result<FoldedPkgbuild, BluelineError> {
    let mut folded = FoldedPkgbuild::default();
    for token in tokens {
        let (name, value) = token
            .split_once('=')
            .ok_or_else(|| pkgbuild_err("token without assignment".to_string()))?;
        if value.starts_with('(') && value.ends_with(')') {
            let body = &value[1..value.len() - 1];
            let elements = split_array_elements(body)?;
            let values = elements
                .iter()
                .map(|element| {
                    if element == "<unknown>" {
                        FoldedValue::Unknown
                    } else {
                        let empty = HashMap::new();
                        resolve_word(&split_words(element).unwrap_or_default(), &empty)
                    }
                })
                .collect();
            folded.arrays.insert(name.to_string(), values);
        } else if value == "<unknown>" {
            folded
                .scalars
                .insert(name.to_string(), FoldedValue::Unknown);
        } else {
            let empty = HashMap::new();
            let resolved = resolve_word(&split_words(value).unwrap_or_default(), &empty);
            folded.scalars.insert(name.to_string(), resolved);
        }
    }
    Ok(folded)
}

const CHECKSUM_ARRAYS: [&str; 8] = [
    "sha256sums",
    "sha384sums",
    "sha512sums",
    "sha224sums",
    "sha1sums",
    "md5sums",
    "b2sums",
    "cksums",
];

fn arrays_matching<'a>(
    folded: &'a FoldedPkgbuild,
    prefix: &str,
) -> Vec<(&'a str, &'a Vec<FoldedValue>)> {
    folded
        .arrays
        .iter()
        .filter(|(name, _)| *name == prefix || name.starts_with(&format!("{prefix}_")))
        .map(|(name, values)| (name.as_str(), values))
        .collect()
}

fn known_text(value: &FoldedValue) -> Option<&str> {
    match value {
        FoldedValue::Known(text) => Some(text),
        FoldedValue::Unknown => None,
    }
}

const META_ARRAYS: [&str; 5] = [
    "source",
    "depends",
    "makedepends",
    "optdepends",
    "checkdepends",
];

fn has_true_indirection(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == b'$' && bytes[i + 1] == b'{' && bytes[i + 2] == b'!' {
            let mut j = i + 3;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            if j <= i + 3 || j >= bytes.len() {
                i = j.max(i + 1);
                continue;
            }
            // `${!name}` is true indirection. `${!arr[@]}`, `${!pre*}`,
            // `${!pre@}` list keys instead and stay quiet.
            match bytes[j] {
                b'}' | b':' | b'/' | b'#' | b'%' | b'^' | b',' | b'-' | b'+' | b'=' | b'?' => {
                    return true;
                }
                _ => {}
            }
            i = j;
        } else {
            i += 1;
        }
    }
    false
}
fn array_is_meta(name: &str) -> bool {
    META_ARRAYS
        .iter()
        .any(|prefix| name == *prefix || name.starts_with(&format!("{prefix}_")))
}

fn contains_cmd_subst(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let mut in_single = false;
    while i < chars.len() {
        let ch = chars[i];
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if ch == '\'' {
            in_single = true;
            i += 1;
            continue;
        }
        if ch == '\\' {
            i += 2;
            continue;
        }
        if ch == '`' {
            return true;
        }
        if ch == '$' && i + 1 < chars.len() && chars[i + 1] == '(' {
            return true;
        }
        i += 1;
    }
    false
}
fn split_brace_once(word: &str) -> Vec<String> {
    let chars: Vec<char> = word.chars().collect();
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '\\' && !in_single {
            i += 2;
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if ch == '"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if ch == '\'' {
            in_single = true;
        } else if ch == '"' {
            in_double = true;
        } else if ch == '{' {
            break;
        }
        i += 1;
    }
    if i >= chars.len() {
        return vec![word.to_string()];
    }
    let mut depth = 0usize;
    let mut in_s = false;
    let mut in_d = false;
    let mut j = i;
    let mut end = None;
    while j < chars.len() {
        let ch = chars[j];
        if ch == '\\' && !in_s {
            j += 2;
            continue;
        }
        if in_s {
            if ch == '\'' {
                in_s = false;
            }
            j += 1;
            continue;
        }
        if in_d {
            if ch == '"' {
                in_d = false;
            }
            j += 1;
            continue;
        }
        match ch {
            '\'' => in_s = true,
            '"' => in_d = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(j);
                    break;
                }
            }
            _ => {}
        }
        j += 1;
    }
    let Some(close) = end else {
        return vec![word.to_string()];
    };
    let prefix: String = chars[..i].iter().collect();
    let inner: String = chars[i + 1..close].iter().collect();
    let suffix: String = chars[close + 1..].iter().collect();
    let mut alternatives = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut in_s = false;
    let mut in_d = false;
    let inner_chars: Vec<char> = inner.chars().collect();
    let mut k = 0;
    while k < inner_chars.len() {
        let ch = inner_chars[k];
        if ch == '\\' && !in_s {
            current.push(ch);
            if k + 1 < inner_chars.len() {
                current.push(inner_chars[k + 1]);
                k += 1;
            }
            k += 1;
            continue;
        }
        if in_s {
            current.push(ch);
            if ch == '\'' {
                in_s = false;
            }
            k += 1;
            continue;
        }
        if in_d {
            current.push(ch);
            if ch == '"' {
                in_d = false;
            }
            k += 1;
            continue;
        }
        match ch {
            '\'' => {
                in_s = true;
                current.push(ch);
            }
            '"' => {
                in_d = true;
                current.push(ch);
            }
            '{' => {
                depth += 1;
                current.push(ch);
            }
            '}' => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if depth == 0 => {
                alternatives.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
        k += 1;
    }
    alternatives.push(current);
    if alternatives.len() < 2 {
        return vec![word.to_string()];
    }
    alternatives
        .into_iter()
        .map(|alt| format!("{prefix}{alt}{suffix}"))
        .collect()
}

fn expand_braces(word: &str) -> (Vec<String>, bool) {
    let mut out = vec![word.to_string()];
    for _ in 0..4 {
        let mut next = Vec::new();
        let mut changed = false;
        for item in &out {
            let parts = split_brace_once(item);
            if parts.len() > 1 || parts.first().is_some_and(|first| first != item) {
                changed = true;
            }
            next.extend(parts);
            if next.len() > 64 {
                return (next, true);
            }
        }
        out = next;
        if !changed {
            break;
        }
    }
    (out, false)
}

fn is_vcs_url(url: &str) -> bool {
    let lower: String = url.to_lowercase();
    ["git+", "hg+", "svn+", "bzr+"]
        .iter()
        .any(|scheme| lower.starts_with(scheme))
}

fn url_covered_by_sig_or_vcs(url: &str) -> bool {
    if is_vcs_url(url) {
        return true;
    }
    let base = url.split('#').next().unwrap_or(url).to_lowercase();
    base.ends_with(".sig") || base.ends_with(".asc") || base.ends_with(".sign")
}

fn paired_source<'a>(folded: &'a FoldedPkgbuild, sum_name: &str) -> Option<&'a Vec<FoldedValue>> {
    for stem in CHECKSUM_ARRAYS {
        if let Some(suffix) = sum_name.strip_prefix(stem)
            && (suffix.is_empty() || suffix.starts_with('_'))
        {
            let source_name = format!("source{suffix}");
            if let Some(values) = folded.arrays.get(&source_name) {
                return Some(values);
            }
        }
    }
    None
}

fn check_r11(folded: &FoldedPkgbuild) -> Vec<PkgFinding> {
    let mut skipped: Vec<String> = Vec::new();
    for array in CHECKSUM_ARRAYS {
        for (name, values) in arrays_matching(folded, array) {
            let sources = paired_source(folded, name);
            let keys_present = arrays_matching(folded, "validpgpkeys")
                .iter()
                .flat_map(|(_, values)| values.iter())
                .filter_map(known_text)
                .any(|key| !key.trim().is_empty());
            for (idx, value) in values.iter().enumerate() {
                if !matches!(value, FoldedValue::Known(text) if text.eq_ignore_ascii_case("SKIP")) {
                    continue;
                }
                // A SKIP is covered when the paired source entry is VCS
                // (commit-pinned, nothing to checksum) or a signature file
                // backed by validpgpkeys. Unknown or unpaired entries stay
                // loud: fail closed.
                let covered = sources
                    .and_then(|urls| urls.get(idx))
                    .and_then(known_text)
                    .is_some_and(|url| {
                        is_vcs_url(url) || (keys_present && url_covered_by_sig_or_vcs(url))
                    });
                if !covered {
                    skipped.push(format!("{name}[{idx}]"));
                }
            }
        }
    }
    if skipped.is_empty() {
        return Vec::new();
    }
    // INFO until tuned: the benign corpus shows real maintainers skip
    // verification routinely (spotify indexed SKIPs, dropbox, nightly -bin
    // balls, -git VCS balls). The signal is true but too loud for HIGH.
    vec![PkgFinding {
        rule_id: "R11_CHECKSUM_SKIP".to_string(),
        severity: VerdictBand::Low,
        evidence: format!("checksum SKIP without signed story: {}", skipped.join(", ")),
    }]
}

fn source_known_urls(folded: &FoldedPkgbuild) -> (Vec<String>, bool) {
    let mut urls = Vec::new();
    let mut blind = false;
    for (_, values) in arrays_matching(folded, "source") {
        for value in values {
            match known_text(value) {
                Some(url) => urls.push(url.to_string()),
                None => blind = true,
            }
        }
    }
    urls.sort();
    (urls, blind)
}

fn check_r12_pair(baseline: &FoldedPkgbuild, target: &FoldedPkgbuild) -> Vec<PkgFinding> {
    let (base_urls, base_blind) = source_known_urls(baseline);
    let (target_urls, target_blind) = source_known_urls(target);
    let mut findings = Vec::new();
    if base_blind || target_blind {
        // Fail-closed lean: unresolvable entries make the drift check blind.
        findings.push(PkgFinding {
            rule_id: "R12_SOURCE_URL_DRIFT".to_string(),
            severity: VerdictBand::Low,
            evidence: "source entries unresolvable; drift comparison blind".to_string(),
        });
    }
    if base_urls == target_urls {
        return findings;
    }
    let base_ver = baseline.scalars.get("pkgver").and_then(known_text);
    let target_ver = target.scalars.get("pkgver").and_then(known_text);
    // A pkgver bump explains URL movement. Unknown versions cannot prove a
    // bump, so the comparison still runs: fail closed.
    if base_ver.is_some() && target_ver.is_some() && base_ver != target_ver {
        return findings;
    }
    let changed: Vec<String> = target_urls
        .iter()
        .filter(|url| !base_urls.contains(url))
        .take(3)
        .cloned()
        .collect();
    if changed.is_empty() {
        return findings;
    }
    findings.push(PkgFinding {
        rule_id: "R12_SOURCE_URL_DRIFT".to_string(),
        severity: VerdictBand::Medium,
        evidence: format!(
            "source URL changed while pkgver stayed `{}`: {}",
            target_ver.or(base_ver).unwrap_or("?"),
            changed.join(", ")
        ),
    });
    findings
}

fn array_lookup(folded: &FoldedPkgbuild, name: &str, subscript: Option<&str>) -> Option<String> {
    let values = folded.arrays.get(name)?;
    match subscript {
        None => values.first().and_then(known_text).map(str::to_string),
        Some(s) if s == "@" || s == "*" => {
            let parts: Vec<&str> = values.iter().filter_map(known_text).collect();
            if parts.len() == values.len() && !parts.is_empty() {
                Some(parts.join(" "))
            } else {
                None
            }
        }
        Some(s) => s
            .parse::<usize>()
            .ok()
            .and_then(|idx| values.get(idx))
            .and_then(known_text)
            .map(str::to_string),
    }
}

fn fold_body_vars(body: &str, folded: &FoldedPkgbuild) -> String {
    let mut out = String::with_capacity(body.len());
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    let emit = |out: &mut String, original: &str, resolved: Option<String>| match resolved {
        Some(value) => out.push_str(&value),
        None => out.push_str(original),
    };
    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() {
            if chars[i + 1] == '{' {
                if let Some(end) = chars[i + 2..].iter().position(|c| *c == '}') {
                    let inner: String = chars[i + 2..i + 2 + end].iter().collect();
                    let original: String = chars[i..i + 2 + end + 1].iter().collect();
                    let resolved = match inner.split_once('[') {
                        None => folded
                            .scalars
                            .get(&inner)
                            .and_then(known_text)
                            .map(str::to_string)
                            .or_else(|| array_lookup(folded, &inner, None)),
                        Some((arr, rest)) => {
                            let sub = rest.strip_suffix(']').unwrap_or(rest);
                            array_lookup(folded, arr, Some(sub))
                        }
                    };
                    emit(&mut out, &original, resolved);
                    i += 2 + end + 1;
                    continue;
                }
            } else if is_name_char(chars[i + 1], true) {
                let mut j = i + 1;
                while j < chars.len() && is_name_char(chars[j], false) {
                    j += 1;
                }
                let name: String = chars[i + 1..j].iter().collect();
                let original: String = chars[i..j].iter().collect();
                let resolved = folded
                    .scalars
                    .get(&name)
                    .and_then(known_text)
                    .map(str::to_string)
                    .or_else(|| array_lookup(folded, &name, None));
                emit(&mut out, &original, resolved);
                i = j;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Match-time normalization for shell text: decode `$'...'` spans and drop
/// quote characters so `"cu"rl`, `$'\x63url'`, and `b"a"sh` match as the
/// shell sees them. Evidence strings always use the original line.
fn normalize_body_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' && i + 2 < chars.len() && chars[i + 1] == '\'' {
            let mut j = i + 2;
            let mut body = String::new();
            let mut closed = false;
            while j < chars.len() {
                if chars[j] == '\\' && j + 1 < chars.len() {
                    body.push(chars[j]);
                    body.push(chars[j + 1]);
                    j += 2;
                    continue;
                }
                if chars[j] == '\'' {
                    closed = true;
                    break;
                }
                body.push(chars[j]);
                j += 1;
            }
            if closed {
                match decode_ansi_c(&body) {
                    Ok(decoded) => out.push_str(&decoded),
                    Err(_) => out.push_str(&chars[i..=j].iter().collect::<String>()),
                }
                i = j + 1;
                continue;
            }
        }
        if chars[i] == '"' || chars[i] == '\'' {
            i += 1;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn shell_bodies(folded: &FoldedPkgbuild) -> Vec<(&str, &str)> {
    folded
        .func_bodies
        .iter()
        .map(|(name, body)| (name.as_str(), body.as_str()))
        .collect()
}

fn line_matches_pipe_to_shell(line: &str) -> bool {
    let lower = line.to_lowercase();
    let pipe = lower.find('|').unwrap_or(usize::MAX);
    if pipe == usize::MAX {
        return false;
    }
    let (left, right) = lower.split_at(pipe);
    let fetcher = ["curl", "wget", "aria2c", "axel"]
        .iter()
        .any(|tool| left.contains(tool));
    if !fetcher {
        return false;
    }
    let shell_hits = ["bash", "sh", "dash", "zsh", "fish"].iter().any(|shell| {
        right
            .split_whitespace()
            .any(|word| word.trim_matches(';') == *shell)
    });
    fetcher && shell_hits
}

fn check_r13(folded: &FoldedPkgbuild) -> Vec<PkgFinding> {
    let bodies = shell_bodies(folded);
    for (name, body) in &bodies {
        let resolved = fold_body_vars(body, folded);
        for line in resolved.lines() {
            let norm = normalize_body_line(line);
            if line_matches_pipe_to_shell(&norm) {
                let short: String = line.trim().chars().take(120).collect();
                return vec![PkgFinding {
                    rule_id: "R13_PIPE_TO_SHELL".to_string(),
                    severity: VerdictBand::High,
                    evidence: format!("{name}(): {short}"),
                }];
            }
        }
    }
    Vec::new()
}

fn is_eval_word(word: &str) -> bool {
    if word == "eval" {
        return true;
    }
    word.strip_prefix("eval")
        .is_some_and(|tail| matches!(tail.chars().next(), Some('"' | '\'' | '$' | '`' | '(')))
}

fn check_r14(folded: &FoldedPkgbuild) -> Vec<PkgFinding> {
    let bodies = shell_bodies(folded);
    for (name, body) in &bodies {
        let resolved = fold_body_vars(body, folded);
        for line in resolved.lines() {
            let norm = normalize_body_line(line);
            let norm = norm.replace("${IFS}", " ").replace("$IFS", " ");
            let lower = norm.to_lowercase();
            let words: Vec<&str> = lower.split_whitespace().collect();
            if words.iter().any(|word| is_eval_word(word)) {
                // Static-only eval (freerdp's `eval "depends+=(...)"`) is a
                // benign conditional-depends idiom. Only dynamic payloads,
                // pipes, and fetchers indicate remote-code risk.
                let dynamic = lower.contains('$')
                    || lower.contains('`')
                    || lower.contains('|')
                    || lower.contains(';')
                    || lower.contains("curl")
                    || lower.contains("wget")
                    || lower.contains("bash");
                if !dynamic {
                    continue;
                }
                let short: String = line.trim().chars().take(120).collect();
                return vec![PkgFinding {
                    rule_id: "R14_EVAL_FAMILY".to_string(),
                    severity: VerdictBand::High,
                    evidence: format!("{name}(): {short}"),
                }];
            }
            if (words.first() == Some(&"source") || words.first() == Some(&"."))
                && let Some(arg) = words.get(1)
            {
                if arg.starts_with("http://") || arg.starts_with("https://") {
                    let short: String = line.trim().chars().take(120).collect();
                    return vec![PkgFinding {
                        rule_id: "R14_EVAL_FAMILY".to_string(),
                        severity: VerdictBand::High,
                        evidence: format!("{name}(): remote source {short}"),
                    }];
                }
                if *arg == "<(" || arg.starts_with("<(") {
                    let short: String = line.trim().chars().take(120).collect();
                    return vec![PkgFinding {
                        rule_id: "R14_EVAL_FAMILY".to_string(),
                        severity: VerdictBand::High,
                        evidence: format!("{name}(): process-substitution source {short}"),
                    }];
                }
                if arg.starts_with('$')
                    || arg.starts_with('`')
                    || *arg == "/dev/stdin"
                    || *arg == "/dev/tcp"
                    || arg.starts_with("/dev/tcp/")
                {
                    let short: String = line.trim().chars().take(120).collect();
                    return vec![PkgFinding {
                        rule_id: "R14_EVAL_FAMILY".to_string(),
                        severity: VerdictBand::Medium,
                        evidence: format!("{name}(): unresolvable source target {short}"),
                    }];
                }
            }
            if let Some(first) = words.first()
                && (first.starts_with("source<") || first.starts_with(".<"))
            {
                let short: String = line.trim().chars().take(120).collect();
                return vec![PkgFinding {
                    rule_id: "R14_EVAL_FAMILY".to_string(),
                    severity: VerdictBand::High,
                    evidence: format!("{name}(): process-substitution source {short}"),
                }];
            }
            let dynamic = lower.contains('$') || lower.contains('`');
            let fetcher = ["curl", "wget"].iter().any(|tool| lower.contains(tool));
            let dash_c = words.windows(2).any(|window| {
                let program = window[0].rsplit('/').next().unwrap_or(window[0]);
                matches!(program, "bash" | "sh" | "dash" | "zsh") && window[1] == "-c"
            });
            if dash_c && (dynamic || fetcher) {
                let short: String = line.trim().chars().take(120).collect();
                return vec![PkgFinding {
                    rule_id: "R14_EVAL_FAMILY".to_string(),
                    severity: VerdictBand::High,
                    evidence: format!("{name}(): dynamic shell -c {short}"),
                }];
            }
        }
    }
    Vec::new()
}

fn check_r23(folded: &FoldedPkgbuild) -> Vec<PkgFinding> {
    let bodies = shell_bodies(folded);
    let managers = ["npm", "bun"];
    let verbs = ["install", "ci", "add", "exec", "run", "x", "dlx"];
    for (name, body) in &bodies {
        let resolved = fold_body_vars(body, folded);
        for line in resolved.lines() {
            let norm = normalize_body_line(line);
            let lower = norm.to_lowercase();
            let words: Vec<&str> = lower.split_whitespace().collect();
            for window in words.windows(2) {
                if managers.contains(&window[0]) && verbs.contains(&window[1]) {
                    // INFO until tuned: source-built electron apps (joplin,
                    // bitwarden-cli, insomnia) genuinely run npm install.
                    // True signal, but ubiquitous in its niche.
                    let short: String = line.trim().chars().take(120).collect();
                    let spec = words.get(2).unwrap_or(&"");
                    return vec![PkgFinding {
                        rule_id: "R23_NPM_DELIVERY".to_string(),
                        severity: VerdictBand::Low,
                        evidence: format!("{name}(): {short} (spec: {spec})"),
                    }];
                }
            }
            if lower.split_whitespace().any(|word| word == "npx") {
                let short: String = line.trim().chars().take(120).collect();
                return vec![PkgFinding {
                    rule_id: "R23_NPM_DELIVERY".to_string(),
                    severity: VerdictBand::Low,
                    evidence: format!("{name}(): {short}"),
                }];
            }
        }
    }
    Vec::new()
}

fn check_r15(folded: &FoldedPkgbuild) -> Vec<PkgFinding> {
    if folded.has_indirection {
        return vec![PkgFinding {
            rule_id: "R15_DYNAMIC_INDIRECTION".to_string(),
            severity: VerdictBand::Medium,
            evidence: "indirect expansion `${!...}` present; value unresolvable".to_string(),
        }];
    }
    Vec::new()
}

fn check_r16(folded: &FoldedPkgbuild) -> Vec<PkgFinding> {
    if folded.meta_subst_arrays.is_empty() {
        return Vec::new();
    }
    vec![PkgFinding {
        rule_id: "R16_CMD_SUBST_IN_META".to_string(),
        severity: VerdictBand::Medium,
        evidence: format!(
            "command substitution in metadata array: {}",
            folded.meta_subst_arrays.join(", ")
        ),
    }]
}

fn check_r17(folded: &FoldedPkgbuild) -> Vec<PkgFinding> {
    let fetchers = [
        "curl", "wget", "aria2c", "axel", "lftp", "ftp", "scp", "rsync", "pip",
    ];
    let bodies = shell_bodies(folded);
    for (name, body) in &bodies {
        if name == &"pkgver" {
            continue;
        }
        let resolved = fold_body_vars(body, folded);
        for line in resolved.lines() {
            let norm = normalize_body_line(line);
            let lower = norm.to_lowercase();
            let words: Vec<&str> = lower.split_whitespace().collect();
            let hit = words.iter().any(|word| fetchers.contains(word))
                || lower.contains("git clone")
                || lower.contains("git fetch");
            if hit {
                // INFO until tuned: benign builds fetch at build time too
                // (tor-browser-bin pulls checksums to verify, logseq fetches).
                // Intent is unreadable statically, so this stays surface-only.
                let short: String = line.trim().chars().take(120).collect();
                return vec![PkgFinding {
                    rule_id: "R17_BUILD_TIME_NETWORK".to_string(),
                    severity: VerdictBand::Low,
                    evidence: format!("{name}(): network fetch {short}"),
                }];
            }
        }
    }
    Vec::new()
}

fn check_r18(folded: &FoldedPkgbuild) -> Vec<PkgFinding> {
    if folded.suspicious_unicode {
        return vec![PkgFinding {
            rule_id: "R18_HOMOGLYPH".to_string(),
            severity: VerdictBand::High,
            evidence: "zero-width, BiDi, or invisible unicode present".to_string(),
        }];
    }
    Vec::new()
}

fn render_known_list(values: &[FoldedValue]) -> Vec<String> {
    values
        .iter()
        .map(|value| match value {
            FoldedValue::Known(text) => text.clone(),
            FoldedValue::Unknown => "<unknown>".to_string(),
        })
        .collect()
}

fn check_r19_pair(baseline: &FoldedPkgbuild, target: &FoldedPkgbuild) -> Vec<PkgFinding> {
    let mut base_keys: Vec<String> = arrays_matching(baseline, "validpgpkeys")
        .iter()
        .flat_map(|(_, values)| render_known_list(values))
        .collect();
    let mut target_keys: Vec<String> = arrays_matching(target, "validpgpkeys")
        .iter()
        .flat_map(|(_, values)| render_known_list(values))
        .collect();
    base_keys.sort();
    target_keys.sort();
    if base_keys == target_keys {
        return Vec::new();
    }
    if base_keys.iter().any(|key| key == "<unknown>")
        || target_keys.iter().any(|key| key == "<unknown>")
    {
        return vec![PkgFinding {
            rule_id: "R19_VALIDPGPKEYS_CHANGE".to_string(),
            severity: VerdictBand::Low,
            evidence: "validpgpkeys unresolvable; cannot compare across releases".to_string(),
        }];
    }
    vec![PkgFinding {
        rule_id: "R19_VALIDPGPKEYS_CHANGE".to_string(),
        severity: VerdictBand::Medium,
        evidence: format!(
            "validpgpkeys changed: [{}] -> [{}]",
            base_keys.join(", "),
            target_keys.join(", ")
        ),
    }]
}

fn check_r21(folded: &FoldedPkgbuild) -> Vec<PkgFinding> {
    for (_, values) in arrays_matching(folded, "source") {
        for value in values {
            let Some(url) = known_text(value) else {
                continue;
            };
            if !is_vcs_url(url) {
                continue;
            }
            let pinned = url
                .split('#')
                .skip(1)
                .flat_map(|fragment| fragment.split('&'))
                .any(|part| part.starts_with("tag=") || part.starts_with("commit="));
            if !pinned {
                // INFO until tuned: bare `git+https://` tracking HEAD is the
                // AUR -git norm (two dozen corpus hits). True but ubiquitous.
                let short: String = url.chars().take(120).collect();
                return vec![PkgFinding {
                    rule_id: "R21_UNPINNED_VCS_SOURCE".to_string(),
                    severity: VerdictBand::Low,
                    evidence: format!("unpinned VCS source without #tag= or #commit=: {short}"),
                }];
            }
        }
    }
    Vec::new()
}

fn strip_token(word: &str) -> &str {
    word.trim_matches(['"', '\'', ';', '(', ')', ',', '`', '{', '}'])
        .trim_start_matches("$(")
        .trim_start_matches('$')
}

fn check_r22(folded: &FoldedPkgbuild) -> Vec<PkgFinding> {
    let bodies = shell_bodies(folded);
    for (name, body) in &bodies {
        let resolved = fold_body_vars(body, folded);
        for line in resolved.lines() {
            let norm = normalize_body_line(line);
            let lower = norm.to_lowercase();
            let words: Vec<&str> = lower.split_whitespace().collect();
            let clean: Vec<&str> = words.iter().map(|word| strip_token(word)).collect();
            let guard = words.iter().zip(clean.iter()).any(|(raw, word)| {
                (raw.starts_with('$') && matches!(word, &"euid" | &"uid" | &"random" | &"srandom"))
                    || matches!(word, &"/dev/urandom" | &"shuf")
            }) || clean.windows(2).any(|window| window == ["id", "-u"])
                || (clean.contains(&"date") && (lower.contains("$(") || lower.contains('`')));
            if guard {
                // INFO until tuned: build-metadata stamps (lazygit ldflags
                // date) and port helpers (syncthingtray shuf) trip this.
                // Cannot prove intent, so surface only.
                let short: String = line.trim().chars().take(120).collect();
                return vec![PkgFinding {
                    rule_id: "R22_CONDITIONAL_EXECUTION".to_string(),
                    severity: VerdictBand::Low,
                    evidence: format!("{name}(): conditional guard {short}"),
                }];
            }
        }
    }
    Vec::new()
}

pub fn check(folded: &FoldedPkgbuild) -> Vec<PkgFinding> {
    let mut findings = Vec::new();
    findings.extend(check_r11(folded));
    findings.extend(check_r13(folded));
    findings.extend(check_r14(folded));
    findings.extend(check_r23(folded));
    findings.extend(check_r15(folded));
    findings.extend(check_r16(folded));
    findings.extend(check_r17(folded));
    findings.extend(check_r18(folded));
    findings.extend(check_r21(folded));
    findings.extend(check_r22(folded));
    findings
}

pub fn check_pair(baseline: &FoldedPkgbuild, target: &FoldedPkgbuild) -> Vec<PkgFinding> {
    let mut findings = check_r12_pair(baseline, target);
    findings.extend(check_r19_pair(baseline, target));
    findings
}

pub fn review_text(content: &str) -> Result<Vec<PkgFinding>, BluelineError> {
    let folded = parse_pkgbuild(content)?;
    Ok(check(&folded))
}

fn rule_title(rule_id: &str) -> &str {
    match rule_id {
        "R11_CHECKSUM_SKIP" => "Checksum SKIP without a signed story",
        "R12_SOURCE_URL_DRIFT" => "Source URL drifted while pkgver stayed",
        "R13_PIPE_TO_SHELL" => "Pipe-to-shell in build script",
        "R14_EVAL_FAMILY" => "Eval or remote-source execution",
        "R15_DYNAMIC_INDIRECTION" => "Dynamic variable indirection",
        "R16_CMD_SUBST_IN_META" => "Command substitution in metadata",
        "R17_BUILD_TIME_NETWORK" => "Network fetch at build time",
        "R18_HOMOGLYPH" => "Suspicious unicode in PKGBUILD",
        "R19_VALIDPGPKEYS_CHANGE" => "Validpgpkeys changed since baseline",
        "R20_INSTALL_HOOK_CHANGE" => "Install or hook file changed",
        "R21_UNPINNED_VCS_SOURCE" => "Unpinned VCS source",
        "R22_CONDITIONAL_EXECUTION" => "Conditional execution guard",
        "R23_NPM_DELIVERY" => "npm or bun delivery at build time",
        _ => "PKGBUILD finding",
    }
}

fn install_hook_touched(delta: &crate::diff::Delta, install_names: &[String]) -> Vec<String> {
    let mut touched = Vec::new();
    let relevant = delta
        .files_added
        .iter()
        .chain(delta.files_removed.iter())
        .chain(delta.files_modified.iter());
    for change in relevant {
        let path = change.relative_path.to_lowercase();
        if path.ends_with(".install")
            || path.ends_with(".hook")
            || install_names.iter().any(|name| path == name.to_lowercase())
        {
            touched.push(change.relative_path.clone());
        }
    }
    touched.sort();
    touched.dedup();
    touched
}

fn install_script_names(folded: &FoldedPkgbuild) -> Vec<String> {
    match folded.scalars.get("install").and_then(known_text) {
        Some(name) if !name.trim().is_empty() => vec![name.trim().to_string()],
        _ => Vec::new(),
    }
}

/// Full AUR review over extracted roots. Target PKGBUILD always reviewed;
/// baseline pair rules (R12, R19) run when the baseline text is available;
/// R20 scans the file delta for .install/.hook changes. Any parse failure
/// is a HIGH finding, never a silent skip.
pub fn review_roots(
    target_root: &std::path::Path,
    baseline_pkgbuild: Option<&str>,
    delta: &crate::diff::Delta,
) -> Vec<crate::verdict::Finding> {
    let mut findings = Vec::new();
    let push = |findings: &mut Vec<crate::verdict::Finding>, item: &PkgFinding| {
        findings.push(crate::verdict::Finding {
            rule_id: item.rule_id.clone(),
            severity: item.severity,
            title: rule_title(&item.rule_id).to_string(),
            description: item.evidence.clone(),
        });
    };
    let target_raw = std::fs::read_to_string(target_root.join("PKGBUILD")).unwrap_or_default();
    if target_raw.is_empty() {
        findings.push(crate::verdict::Finding {
            rule_id: "R00_PKGBUILD_UNREADABLE".to_string(),
            severity: VerdictBand::High,
            title: "PKGBUILD unreadable".to_string(),
            description: "target PKGBUILD missing or empty; refusing to review blind".to_string(),
        });
        return findings;
    }
    let target_folded = match parse_pkgbuild(&target_raw) {
        Ok(folded) => folded,
        Err(e) => {
            findings.push(crate::verdict::Finding {
                rule_id: "R00_PKGBUILD_UNPARSEABLE".to_string(),
                severity: VerdictBand::High,
                title: "PKGBUILD unparseable".to_string(),
                description: format!("static parse failed fail-closed: {e:#}"),
            });
            return findings;
        }
    };
    for item in check(&target_folded) {
        push(&mut findings, &item);
    }
    if let Some(base_raw) = baseline_pkgbuild {
        match parse_pkgbuild(base_raw) {
            Ok(base_folded) => {
                for item in check_pair(&base_folded, &target_folded) {
                    push(&mut findings, &item);
                }
            }
            Err(e) => findings.push(crate::verdict::Finding {
                rule_id: "R00_BASELINE_UNPARSEABLE".to_string(),
                severity: VerdictBand::High,
                title: "Baseline PKGBUILD unparseable".to_string(),
                description: format!("cannot diff safely: {e:#}"),
            }),
        }
    }
    let mut install_names = install_script_names(&target_folded);
    if let Some(base_raw) = baseline_pkgbuild
        && let Ok(base_folded) = parse_pkgbuild(base_raw)
    {
        install_names.extend(install_script_names(&base_folded));
    }
    let touched = install_hook_touched(delta, &install_names);
    if !touched.is_empty() {
        findings.push(crate::verdict::Finding {
            rule_id: "R20_INSTALL_HOOK_CHANGE".to_string(),
            severity: VerdictBand::Medium,
            title: rule_title("R20_INSTALL_HOOK_CHANGE").to_string(),
            description: format!(".install/.hook changed: {}", touched.join(", ")),
        });
    }
    findings.push(crate::verdict::Finding {
        rule_id: "R00_PKGBUILD_SCOPE".to_string(),
        severity: VerdictBand::Low,
        title: "PKGBUILD review scope".to_string(),
        description:
            "review covers repo scripts only; downloaded upstream sources are not reviewed"
                .to_string(),
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known(folded: &FoldedPkgbuild, name: &str) -> Option<String> {
        match folded.scalars.get(name) {
            Some(FoldedValue::Known(value)) => Some(value.clone()),
            _ => None,
        }
    }

    #[test]
    fn single_quotes_block_expansion() {
        let folded = parse_pkgbuild("pkgver=1.0\npkgdesc='$pkgver rocks'\n").unwrap();
        assert_eq!(known(&folded, "pkgdesc").as_deref(), Some("$pkgver rocks"));
    }

    #[test]
    fn double_quotes_fold_vars() {
        let folded = parse_pkgbuild("pkgver=1.0\nurl=\"https://x/$pkgver.tar.gz\"\n").unwrap();
        assert_eq!(
            known(&folded, "url").as_deref(),
            Some("https://x/1.0.tar.gz")
        );
    }

    #[test]
    fn ansi_c_escapes_fold() {
        let folded = parse_pkgbuild("msg=$'a\\x20b\\nc'\n").unwrap();
        assert_eq!(known(&folded, "msg").as_deref(), Some("a b\nc"));
    }

    #[test]
    fn bad_ansi_c_escape_fails_closed() {
        assert!(parse_pkgbuild("msg=$'a\\xZZ'\n").is_err());
    }

    #[test]
    fn backslash_newline_joins_lines() {
        let folded = parse_pkgbuild("pkgdesc=hello\\\nworld\n").unwrap();
        assert_eq!(known(&folded, "pkgdesc").as_deref(), Some("helloworld"));
    }

    #[test]
    fn comments_strip_unquoted_only() {
        let folded = parse_pkgbuild("pkgver=1.0 # trailing\nquoted=\"a#b\"\n").unwrap();
        assert_eq!(known(&folded, "pkgver").as_deref(), Some("1.0"));
        assert_eq!(known(&folded, "quoted").as_deref(), Some("a#b"));
    }

    #[test]
    fn arch_arrays_stay_separate() {
        let folded = parse_pkgbuild("source=(a b)\nsource_x86_64=(c)\n").unwrap();
        assert_eq!(folded.arrays["source"].len(), 2);
        assert_eq!(folded.arrays["source_x86_64"].len(), 1);
    }

    #[test]
    fn multipass_fold_resolves_chain() {
        let folded = parse_pkgbuild("a=1\nb=$a\npkgver=$b\n").unwrap();
        assert_eq!(known(&folded, "pkgver").as_deref(), Some("1"));
    }

    #[test]
    fn undefined_var_is_unknown_not_empty() {
        let folded = parse_pkgbuild("url=https://x/$missing.tar.gz\n").unwrap();
        assert!(matches!(folded.scalars["url"], FoldedValue::Unknown));
    }

    #[test]
    fn indirection_is_unknown() {
        let folded = parse_pkgbuild("cmd=${!var}\n").unwrap();
        assert!(matches!(folded.scalars["cmd"], FoldedValue::Unknown));
    }

    #[test]
    fn command_subst_in_source_is_unknown() {
        let folded = parse_pkgbuild("source=(\"$(curl x)\")\n").unwrap();
        assert!(matches!(folded.arrays["source"][0], FoldedValue::Unknown));
    }

    #[test]
    fn backtick_in_depends_is_unknown() {
        let folded = parse_pkgbuild("depends=(`date`)\n").unwrap();
        assert!(matches!(folded.arrays["depends"][0], FoldedValue::Unknown));
    }

    #[test]
    fn concat_split_folds_before_match() {
        let folded = parse_pkgbuild("_a=\"cu\" \n_b='rl'\ncmd=\"$_a$_b\"\n").unwrap();
        assert_eq!(known(&folded, "cmd").as_deref(), Some("curl"));
    }

    #[test]
    fn func_bodies_captured_raw() {
        let folded = parse_pkgbuild("pkgver() {\n git describe\n}\nbuild() {\n make\n}\n").unwrap();
        assert!(folded.func_bodies["pkgver"].contains("git describe"));
        assert!(folded.func_bodies["build"].contains("make"));
    }

    #[test]
    fn byte_cap_is_exact() {
        let pad_len = PKGBUILD_MAX_BYTES - "pkgver=1.0\npad=\n".len();
        let raw = format!("pkgver=1.0\npad={}\n", "x".repeat(pad_len));
        assert_eq!(raw.len(), PKGBUILD_MAX_BYTES);
        assert!(parse_pkgbuild(&raw).is_ok());
        let over = format!("{raw}x");
        assert!(parse_pkgbuild(&over).is_err());
    }

    #[test]
    fn unterminated_quote_fails_closed() {
        assert!(parse_pkgbuild("pkgdesc=\"oops\n").is_err());
        assert!(parse_pkgbuild("pkgdesc='oops\n").is_err());
    }

    #[test]
    fn unterminated_subst_fails_closed() {
        assert!(parse_pkgbuild("url=$(curl x\n").is_err());
    }

    #[test]
    fn suspicious_unicode_detected() {
        assert!(contains_suspicious_unicode("cu\u{200B}rl"));
        assert!(!contains_suspicious_unicode("curl"));
    }

    #[test]
    fn tokenize_roundtrip_parses() {
        let folded = parse_pkgbuild("pkgver=1.0\nsource=(a \"$(x)\")\n").unwrap();
        let tokens = tokenize("pkgver=1.0\nsource=(a \"$(x)\")\n").unwrap();
        let back = resolve_vars(&tokens).unwrap();
        assert_eq!(folded.scalars["pkgver"], back.scalars["pkgver"]);
        assert_eq!(folded.arrays["source"], back.arrays["source"]);
    }

    fn empty_delta() -> crate::diff::Delta {
        crate::diff::Delta {
            baseline_version: None,
            target_version: "1.0".to_string(),
            files_added: Vec::new(),
            files_removed: Vec::new(),
            files_modified: Vec::new(),
            total_lines_added: 0,
            total_lines_deleted: 0,
            new_executables: Vec::new(),
            new_binaries: Vec::new(),
            modified_binaries: Vec::new(),
            new_lifecycle_scripts: Vec::new(),
            modified_lifecycle_scripts: Vec::new(),
            new_dependencies: Vec::new(),
            modified_dependencies: Vec::new(),
            removed_dependencies: Vec::new(),
            binding_gyp_added: false,
        }
    }

    fn findings_for(content: &str) -> Vec<PkgFinding> {
        review_text(content).unwrap()
    }

    fn has_rule(findings: &[PkgFinding], rule: &str) -> bool {
        findings.iter().any(|finding| finding.rule_id == rule)
    }

    #[test]
    fn r11_fires_on_bare_skip() {
        let findings = findings_for("source=(foo.tar.gz)\nsha256sums=('SKIP')\n");
        assert!(has_rule(&findings, "R11_CHECKSUM_SKIP"));
    }

    #[test]
    fn r11_quiet_with_signed_story() {
        let findings = findings_for(
            "source=(foo.tar.gz foo.tar.gz.sig)\nsha256sums=(abc SKIP)\nvalidpgpkeys=(ABC123)\n",
        );
        assert!(!has_rule(&findings, "R11_CHECKSUM_SKIP"));
    }

    #[test]
    fn r11_quiet_for_vcs_without_keys() {
        let findings =
            findings_for("source=(git+https://example.com/repo.git)\nsha256sums=('SKIP')\n");
        assert!(!has_rule(&findings, "R11_CHECKSUM_SKIP"));
    }

    #[test]
    fn r11_catches_folded_skip() {
        let findings = findings_for("_a=\"SK\"\nsha256sums=(\"${_a}IP\")\nsource=(a)\n");
        assert!(has_rule(&findings, "R11_CHECKSUM_SKIP"));
    }

    #[test]
    fn r12_fires_on_host_swap_same_pkgver() {
        let base =
            parse_pkgbuild("pkgver=1.0\nsource=(https://good.example/f-1.0.tar.gz)\n").unwrap();
        let target =
            parse_pkgbuild("pkgver=1.0\nsource=(https://evil.example/f-1.0.tar.gz)\n").unwrap();
        let findings = check_pair(&base, &target);
        assert!(has_rule(&findings, "R12_SOURCE_URL_DRIFT"));
    }

    #[test]
    fn r12_quiet_on_pkgver_bump() {
        let base = parse_pkgbuild("pkgver=1.0\nsource=(https://a.example/f-1.0.tar.gz)\n").unwrap();
        let target =
            parse_pkgbuild("pkgver=1.1\nsource=(https://b.example/f-1.1.tar.gz)\n").unwrap();
        assert!(!has_rule(
            &check_pair(&base, &target),
            "R12_SOURCE_URL_DRIFT"
        ));
    }

    #[test]
    fn r12_quiet_on_identical_sources() {
        let base = parse_pkgbuild("pkgver=1.0\nsource=(https://a.example/f.tar.gz)\n").unwrap();
        assert!(check_pair(&base, &base).is_empty());
    }

    #[test]
    fn r13_fires_on_curl_pipe_bash() {
        let findings = findings_for("build() {\n curl -fsSL https://x | bash\n}\n");
        assert!(has_rule(&findings, "R13_PIPE_TO_SHELL"));
    }

    #[test]
    fn r13_quiet_on_curl_to_tar() {
        let findings = findings_for("build() {\n curl -O https://x/f.tar.gz | tar -xz\n}\n");
        assert!(!has_rule(&findings, "R13_PIPE_TO_SHELL"));
    }

    #[test]
    fn r13_catches_folded_fetcher() {
        let findings = findings_for("_c=curl\nbuild() {\n $_c https://x | sh\n}\n");
        assert!(has_rule(&findings, "R13_PIPE_TO_SHELL"));
    }

    #[test]
    fn indexed_assignment_overrides_slot() {
        let folded = parse_pkgbuild("sha256sums=(aaa bbb)\nsha256sums[1]='SKIP'\n").unwrap();
        assert_eq!(
            folded.arrays["sha256sums"],
            vec![
                FoldedValue::Known("aaa".to_string()),
                FoldedValue::Known("SKIP".to_string()),
            ]
        );
        let findings =
            review_text("sha256sums=(aaa bbb)\nsha256sums[1]='SKIP'\nsource=(x)\n").unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "R11_CHECKSUM_SKIP")
        );
    }

    #[test]
    fn brace_expansion_pairs_sig_story() {
        let folded = parse_pkgbuild(
            "source=(\"https://x/MullvadVPN-1.0_amd64.deb\"{,.asc})\nsha256sums=('abc'\n'SKIP')\nvalidpgpkeys=(ABC)\n",
        )
        .unwrap();
        assert_eq!(folded.arrays["source"].len(), 2);
        let findings = review_text(
            "source=(\"https://x/MullvadVPN-1.0_amd64.deb\"{,.asc})\nsha256sums=('abc'\n'SKIP')\nvalidpgpkeys=(ABC)\n",
        )
        .unwrap();
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "R11_CHECKSUM_SKIP")
        );
    }

    #[test]
    fn r14_quiet_on_static_eval() {
        let findings = findings_for("package() {\n eval \"depends+=(qt6-base)\"\n}\n");
        assert!(!has_rule(&findings, "R14_EVAL_FAMILY"));
    }

    #[test]
    fn r14_fires_on_eval() {
        let findings = findings_for("build() {\n eval \"$cmd\"\n}\n");
        assert!(has_rule(&findings, "R14_EVAL_FAMILY"));
    }

    #[test]
    fn r14_fires_on_remote_source() {
        let findings = findings_for("build() {\n source <(curl https://x)\n}\n");
        assert!(has_rule(&findings, "R14_EVAL_FAMILY"));
    }

    #[test]
    fn r14_quiet_on_static_bash_c() {
        let findings = findings_for("build() {\n bash -c \"make -j4\"\n}\n");
        assert!(!has_rule(&findings, "R14_EVAL_FAMILY"));
    }

    #[test]
    fn r23_fires_on_npm_install() {
        let findings = findings_for("build() {\n npm install --cache \"$srcdir/c\"\n}\n");
        assert!(has_rule(&findings, "R23_NPM_DELIVERY"));
        assert!(
            findings
                .iter()
                .any(|finding| finding.evidence.contains("npm"))
        );
    }

    #[test]
    fn r23_fires_on_bun_and_npx() {
        assert!(has_rule(
            &findings_for("package() {\n bun install\n}\n"),
            "R23_NPM_DELIVERY"
        ));
        assert!(has_rule(
            &findings_for("package() {\n npx cowsay hi\n}\n"),
            "R23_NPM_DELIVERY"
        ));
    }

    #[test]
    fn r23_quiet_on_comment_only() {
        let findings = findings_for("pkgdesc='a pack'\n# npm install\nbuild() {\n make\n}\n");
        assert!(!has_rule(&findings, "R23_NPM_DELIVERY"));
    }

    #[test]
    fn hash_inside_word_is_not_a_comment() {
        let folded = parse_pkgbuild("source=(git+https://x/y.git#commit=abc)\n").unwrap();
        assert_eq!(
            folded.arrays["source"],
            vec![FoldedValue::Known(
                "git+https://x/y.git#commit=abc".to_string()
            )]
        );
        let trailing = parse_pkgbuild("pkgver=1.0 # trailing\n").unwrap();
        assert_eq!(
            trailing.scalars["pkgver"],
            FoldedValue::Known("1.0".to_string())
        );
    }

    #[test]
    fn r15_fires_on_true_indirection_only() {
        assert!(has_rule(
            &findings_for("cmd=${!var}\n"),
            "R15_DYNAMIC_INDIRECTION"
        ));
        // Key listing (`${!arr[@]}`, `${!pfx*}`) is standard iteration, quiet.
        let keys = findings_for("for k in \"${!names[@]}\"; do echo $k; done\n");
        assert!(!has_rule(&keys, "R15_DYNAMIC_INDIRECTION"));
    }

    #[test]
    fn r15_quiet_on_plain_default() {
        let findings = findings_for("url=${var:-def}\n");
        assert!(!has_rule(&findings, "R15_DYNAMIC_INDIRECTION"));
    }

    #[test]
    fn r16_fires_in_source_not_pkgver() {
        assert!(has_rule(
            &findings_for("source=(\"$(curl x)\")\n"),
            "R16_CMD_SUBST_IN_META"
        ));
        assert!(has_rule(
            &findings_for("makedepends=(`date`)\n"),
            "R16_CMD_SUBST_IN_META"
        ));
        let vcs = findings_for("pkgver() {\n git describe --tags\n}\n");
        assert!(!has_rule(&vcs, "R16_CMD_SUBST_IN_META"));
    }

    #[test]
    fn r17_fires_in_build_not_source() {
        assert!(has_rule(
            &findings_for("build() {\n curl -O https://x/f.tar.gz\n}\n"),
            "R17_BUILD_TIME_NETWORK"
        ));
        let plain = findings_for("source=(https://x/f.tar.gz)\nbuild() {\n make\n}\n");
        assert!(!has_rule(&plain, "R17_BUILD_TIME_NETWORK"));
    }

    #[test]
    fn r18_fires_on_zero_width() {
        assert!(has_rule(
            &findings_for("cmd=cu\u{200B}rl\n"),
            "R18_HOMOGLYPH"
        ));
        assert!(!has_rule(&findings_for("cmd=curl\n"), "R18_HOMOGLYPH"));
    }

    #[test]
    fn r19_fires_on_key_change() {
        let base = parse_pkgbuild("validpgpkeys=(AAA)\n").unwrap();
        let same = parse_pkgbuild("validpgpkeys=(AAA)\n").unwrap();
        let changed = parse_pkgbuild("validpgpkeys=(BBB)\n").unwrap();
        assert!(check_pair(&base, &same).is_empty());
        assert!(has_rule(
            &check_pair(&base, &changed),
            "R19_VALIDPGPKEYS_CHANGE"
        ));
    }

    #[test]
    fn r21_fires_unpinned_vcs() {
        assert!(has_rule(
            &findings_for("source=(git+https://x/y.git)\n"),
            "R21_UNPINNED_VCS_SOURCE"
        ));
        assert!(has_rule(
            &findings_for("source=(git+https://x/y.git#branch=main)\n"),
            "R21_UNPINNED_VCS_SOURCE"
        ));
        let pinned = findings_for("source=(git+https://x/y.git#tag=v1.2)\n");
        assert!(!has_rule(&pinned, "R21_UNPINNED_VCS_SOURCE"));
        let tarball = findings_for("source=(https://x/f.tar.gz)\n");
        assert!(!has_rule(&tarball, "R21_UNPINNED_VCS_SOURCE"));
    }

    #[test]
    fn multibyte_inside_subst_does_not_panic() {
        let folded = parse_pkgbuild("a=1\nb=$(echo h\u{e9}llo)\n").unwrap();
        assert!(matches!(folded.scalars["b"], FoldedValue::Unknown));
    }

    #[test]
    fn non_ascii_index_becomes_assoc_without_panic() {
        assert!(parse_pkgbuild("a[\u{e9}]=1\n").is_ok());
    }

    #[test]
    fn redirect_hash_is_a_comment() {
        let folded = parse_pkgbuild("pkgver=1.0\nfoo=bar>#x\n").unwrap();
        assert_eq!(
            folded.scalars["foo"],
            FoldedValue::Known("bar>".to_string())
        );
    }

    #[test]
    fn subshell_body_is_scanned() {
        let findings = findings_for("build() (\n curl https://x | bash\n)\n");
        assert!(has_rule(&findings, "R13_PIPE_TO_SHELL"));
    }

    #[test]
    fn hyphenated_package_func_is_scanned() {
        let findings = findings_for("package_foo-bar() {\n curl -O https://x | sh\n}\n");
        assert!(has_rule(&findings, "R13_PIPE_TO_SHELL"));
    }

    #[test]
    fn top_level_shell_is_scanned() {
        let findings = findings_for("curl https://x | bash\npkgver=1.0\n");
        assert!(has_rule(&findings, "R13_PIPE_TO_SHELL"));
    }

    #[test]
    fn r14_fires_through_wrappers_and_spacing() {
        assert!(has_rule(
            &findings_for("build() {\n sudo eval \"$evil\"\n}\n"),
            "R14_EVAL_FAMILY"
        ));
        assert!(has_rule(
            &findings_for("build() {\n command eval \"$evil\"\n}\n"),
            "R14_EVAL_FAMILY"
        ));
        assert!(has_rule(
            &findings_for("build() {\n bash   -c \"$cmd\"\n}\n"),
            "R14_EVAL_FAMILY"
        ));
    }

    #[test]
    fn r11_pairs_skip_to_its_own_source_index() {
        let findings = findings_for(
            "source=(evil.tar.gz good.tar.gz good.tar.gz.sig)\nsha256sums=(SKIP abc SKIP)\nvalidpgpkeys=(K)\n",
        );
        let r11: Vec<&PkgFinding> = findings
            .iter()
            .filter(|finding| finding.rule_id == "R11_CHECKSUM_SKIP")
            .collect();
        assert_eq!(r11.len(), 1);
        assert!(r11[0].evidence.contains("sha256sums[0]"));
        assert!(!r11[0].evidence.contains("sha256sums[2]"));
    }

    #[test]
    fn r12_fires_on_fragment_swap() {
        let base = parse_pkgbuild("pkgver=1.0\nsource=(git+https://x/y.git#tag=v1.0)\n").unwrap();
        let target = parse_pkgbuild("pkgver=1.0\nsource=(git+https://x/y.git#tag=v1.1)\n").unwrap();
        assert!(has_rule(
            &check_pair(&base, &target),
            "R12_SOURCE_URL_DRIFT"
        ));
    }

    #[test]
    fn r15_fires_with_operators_but_not_in_comments() {
        assert!(has_rule(
            &findings_for("cmd=${!var:-def}\n"),
            "R15_DYNAMIC_INDIRECTION"
        ));
        let commented = findings_for("# see ${!var}\npkgver=1.0\n");
        assert!(!has_rule(&commented, "R15_DYNAMIC_INDIRECTION"));
    }

    #[test]
    fn r19_ignores_key_order() {
        let base = parse_pkgbuild("validpgpkeys=(AAA BBB)\n").unwrap();
        let reordered = parse_pkgbuild("validpgpkeys=(BBB AAA)\n").unwrap();
        assert!(check_pair(&base, &reordered).is_empty());
    }

    #[test]
    fn r20_fires_on_install_file_change() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("PKGBUILD"), "pkgver=1.0\n").unwrap();
        let folded = parse_pkgbuild("pkgver=1.0\n").unwrap();
        let mut delta = empty_delta();
        delta.files_modified.push(crate::diff::FileChange {
            relative_path: "demopkg.install".to_string(),
            kind: crate::diff::FileKind::Text,
            lines_added: 1,
            lines_deleted: 0,
            is_executable: false,
            unified_diff: None,
        });
        let findings = review_roots(dir.path(), Some("pkgver=1.0\n"), &delta);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "R20_INSTALL_HOOK_CHANGE")
        );
        let _ = folded;
    }

    #[test]
    fn first_sighting_skips_pair_rules() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("PKGBUILD"), "pkgver=1.0\n").unwrap();
        let delta = empty_delta();
        let findings = review_roots(dir.path(), None, &delta);
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "R12_SOURCE_URL_DRIFT")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "R00_PKGBUILD_SCOPE")
        );
    }

    #[test]
    fn r22_ignores_word_substrings() {
        let flagged = findings_for("build() {\n echo \"valid -u flag\"\n}\n");
        assert!(!has_rule(&flagged, "R22_CONDITIONAL_EXECUTION"));
        let shuffled = findings_for("build() {\n echo shuffled\n}\n");
        assert!(!has_rule(&shuffled, "R22_CONDITIONAL_EXECUTION"));
    }

    #[test]
    fn r22_fires_on_euid_and_random() {
        assert!(has_rule(
            &findings_for("build() {\n if [ $EUID -eq 0 ]; then echo hi; fi\n}\n"),
            "R22_CONDITIONAL_EXECUTION"
        ));
        assert!(has_rule(
            &findings_for("package() {\n echo $RANDOM\n}\n"),
            "R22_CONDITIONAL_EXECUTION"
        ));
        let plain = findings_for("build() {\n make install\n}\n");
        assert!(!has_rule(&plain, "R22_CONDITIONAL_EXECUTION"));
    }
}
