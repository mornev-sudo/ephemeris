//! `ephsh`: the router's own command line. The same commands as `ephctl`,
//! typed without `ephctl` at an `ephsh>` prompt (`ephctl shell`, or the
//! `ephsh` link on the router):
//!
//! ```text
//! cpt-br1> status
//! cpt-br1> config show
//! cpt-br1> help system
//! cpt-br1> exit
//! ```
//!
//! No history or completion: it reads plain lines, so it also takes a
//! script on its input (`ephsh < commands.txt`).

use anyhow::{bail, Result};
use std::io::{BufRead, IsTerminal, Write};

/// Split a command line into words: spaces separate them, quotes ('' or "")
/// keep spaces in one, a backslash takes the next character as it is.
pub fn words(line: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), '\\') | (None, '\\') => match chars.next() {
                Some(n) => cur.push(n),
                None => bail!("a backslash at the end of the line"),
            },
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                in_word = true;
                continue;
            }
            (None, c) if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
                continue;
            }
            (None, c) => cur.push(c),
        }
        in_word = true;
    }
    if quote.is_some() {
        bail!("a quote isn't closed");
    }
    if in_word {
        out.push(cur);
    }
    Ok(out)
}

/// What a line asks for.
#[derive(Debug, PartialEq)]
pub enum Line {
    Nothing,
    Exit,
    /// `ephctl` arguments (after the program name).
    Run(Vec<String>),
}

pub fn parse(line: &str) -> Result<Line> {
    let mut w = words(line.trim())?;
    Ok(match w.first().map(String::as_str) {
        None => Line::Nothing,
        Some(c) if c.starts_with('#') => Line::Nothing,
        Some("exit" | "quit" | "logout") => Line::Exit,
        // "help" and "?": the command list; "help system": that command's.
        Some("help" | "?") => {
            w.remove(0);
            w.push("--help".into());
            Line::Run(w)
        }
        // Typed out of habit.
        Some("ephctl") => {
            w.remove(0);
            Line::Run(w)
        }
        _ => Line::Run(w),
    })
}

/// Read commands until `exit` or the end of the input. Each runs with
/// `global` (the shell's own --url and --token) and `exec`; a failing one
/// prints its error and the shell carries on.
pub fn run(global: &[String], exec: impl Fn(Vec<String>) -> Result<()>) -> Result<()> {
    let tty = std::io::stdin().is_terminal();
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "ephsh".into());
    if tty {
        println!("Ephemeris router shell. Type help for commands, exit to leave.");
    }
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        if tty {
            print!("{host}> ");
            std::io::stdout().flush()?;
        }
        let Some(line) = lines.next() else {
            if tty {
                println!();
            }
            return Ok(());
        };
        match parse(&line?) {
            Ok(Line::Nothing) => {}
            Ok(Line::Exit) => return Ok(()),
            Ok(Line::Run(w)) if w.first().is_some_and(|c| c == "shell") => {
                eprintln!("already in the shell");
            }
            Ok(Line::Run(w)) => {
                let mut args = vec!["ephctl".to_string()];
                args.extend(global.iter().cloned());
                args.extend(w);
                if let Err(e) = exec(args) {
                    eprintln!("error: {e:#}");
                }
            }
            Err(e) => eprintln!("error: {e:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_split_like_a_shell() {
        assert_eq!(
            words("  route add 0.0.0.0/0  10.0.0.1 ").unwrap(),
            ["route", "add", "0.0.0.0/0", "10.0.0.1"]
        );
        assert_eq!(
            words(r#"log show -c "dhcp server" 'a b'"#).unwrap(),
            ["log", "show", "-c", "dhcp server", "a b"]
        );
        assert_eq!(words(r"a\ b c").unwrap(), ["a b", "c"]);
        assert_eq!(words(r#"x """#).unwrap(), ["x", ""]);
        assert!(words("say \"unclosed").is_err());
        assert!(words("trailing \\").is_err());
    }

    #[test]
    fn what_a_line_asks_for() {
        assert_eq!(parse("").unwrap(), Line::Nothing);
        assert_eq!(parse("  # a comment").unwrap(), Line::Nothing);
        assert_eq!(parse("exit").unwrap(), Line::Exit);
        assert_eq!(parse("status").unwrap(), Line::Run(vec!["status".into()]));
        assert_eq!(parse("ephctl wan").unwrap(), Line::Run(vec!["wan".into()]));
        assert_eq!(parse("?").unwrap(), Line::Run(vec!["--help".into()]));
        assert_eq!(
            parse("help system").unwrap(),
            Line::Run(vec!["system".into(), "--help".into()])
        );
    }
}
