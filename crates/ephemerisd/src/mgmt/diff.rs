//! A small line diff (longest common subsequence), enough to show what a
//! config change will do before committing it.

/// Most cells the LCS table may have (4 bytes each: 16 MiB). Common leading
/// and trailing lines are taken off first, so an ordinary edit is tiny; a
/// change bigger than this is shown as the old lines replaced by the new.
const MAX_CELLS: usize = 4 << 20;

/// Unified-style diff of two texts: changed lines prefixed with `-`/`+`,
/// up to `CONTEXT` unchanged lines around each change, `…` for the rest.
/// Empty string when the texts are identical. Time and memory are bounded
/// whatever the input (see [`MAX_CELLS`]).
pub fn diff(old: &str, new: &str) -> String {
    const CONTEXT: usize = 2;
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    if a == b {
        return String::new();
    }
    // Unchanged lines at the start and end need no alignment.
    let pre = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let suf = a[pre..]
        .iter()
        .rev()
        .zip(b[pre..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (am, bm) = (&a[pre..a.len() - suf], &b[pre..b.len() - suf]);
    let mut ops: Vec<(char, &str)> = a[..pre].iter().map(|l| (' ', *l)).collect();
    if am.len().saturating_mul(bm.len()) > MAX_CELLS {
        ops.extend(am.iter().map(|l| ('-', *l)));
        ops.extend(bm.iter().map(|l| ('+', *l)));
    } else {
        lcs_ops(am, bm, &mut ops);
    }
    ops.extend(a[a.len() - suf..].iter().map(|l| (' ', *l)));

    // Keep only context near changes.
    let mut near = vec![false; ops.len()];
    for (k, (op, _)) in ops.iter().enumerate() {
        if *op != ' ' {
            let end = (k + CONTEXT).min(ops.len() - 1);
            near[k.saturating_sub(CONTEXT)..=end].fill(true);
        }
    }
    let mut out = String::new();
    let mut skipped = false;
    for (k, (op, line)) in ops.iter().enumerate() {
        if *op == ' ' && !near[k] {
            if !skipped {
                out.push_str("  …\n");
                skipped = true;
            }
            continue;
        }
        skipped = false;
        out.push(*op);
        out.push(' ');
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Line-by-line alignment of `a` and `b` (LCS), as diff operations.
fn lcs_ops<'a>(a: &[&'a str], b: &[&'a str], ops: &mut Vec<(char, &'a str)>) {
    // lcs[i][j] = length of the LCS of a[i..] and b[j..]
    let mut lcs = vec![vec![0u32; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            ops.push((' ', a[i]));
            i += 1;
            j += 1;
        } else if i < a.len() && (j == b.len() || lcs[i + 1][j] >= lcs[i][j + 1]) {
            // Deletions before insertions, like `diff -u`.
            ops.push(('-', a[i]));
            i += 1;
        } else {
            ops.push(('+', b[j]));
            j += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::diff;

    #[test]
    fn identical_is_empty() {
        assert_eq!(diff("a\nb\n", "a\nb\n"), "");
    }

    #[test]
    fn shows_changes_with_context() {
        let old = "1\n2\n3\n4\n5\n6\n7\n8\n";
        let new = "1\n2\n3\n4\nfive\n6\n7\n8\n";
        assert_eq!(
            diff(old, new),
            "  …\n  3\n  4\n- 5\n+ five\n  6\n  7\n  …\n"
        );
    }

    #[test]
    fn appended_lines() {
        assert_eq!(diff("a\n", "a\nb\n"), "  a\n+ b\n");
    }

    #[test]
    fn huge_rewrites_stay_cheap() {
        // Every other line changed in 20 000 lines: a full LCS table would be
        // 1.6 GB. Shown as replaced instead, quickly.
        let old: String = (0..20_000).map(|i| format!("# c{i}\n")).collect();
        let new: String = (0..20_000)
            .map(|i| {
                if i % 2 == 0 {
                    format!("# c{i}\n")
                } else {
                    format!("# x{i}\n")
                }
            })
            .collect();
        let t = std::time::Instant::now();
        let d = diff(&old, &new);
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
        assert!(d.starts_with("  # c0\n- # c1\n"), "{}", &d[..40]);
        assert_eq!(d.lines().count(), 1 + 2 * 19_999);
    }
}
