//! Reading bookmarks out of installed browsers.
//!
//! SCOPE: the Chromium family only — Chrome, Brave, Edge, Vivaldi, Opera.
//! They all write the same `Bookmarks` JSON file, so one reader covers every
//! one of them with no new dependency. Firefox keeps its bookmarks in
//! `places.sqlite` and Safari in a binary plist; each needs a parser this crate
//! does not have yet, and neither is here. That is a deliberate first slice,
//! not an oversight — see docs/BOOKMARKS.md.
//!
//! NOT THE PRIMARY IMPORT PATH, and this is worth knowing before reaching for
//! it. On macOS 27 reading another app's `~/Library/Application Support/<app>`
//! is refused with EPERM unless the reader has FULL DISK ACCESS — measured, not
//! assumed: an `ls` of the Chrome profile directory fails for an ordinary
//! process on this machine today. Asking a password manager's user to grant
//! Full Disk Access, so it can read files a browser extension hands over for
//! free, is a bad trade and a worse look.
//!
//! The extension route needs no file access, no per-OS profile hunting and no
//! TCC prompt, and it is the same channel the push-out direction needs anyway.
//! This module stays for the cases the extension cannot reach — chiefly Safari,
//! which has no bookmarks API for web extensions at all — and those cases will
//! have to ask for the permission openly.
//!
//! NOTHING HERE WRITES. Discovery and reading only: a bug in this file can
//! misread someone's bookmarks, never destroy them.
//!
//! The tree is flattened to folder PATHS ("Bar/Arbeid/Kunder"). The vault has
//! no hierarchy and does not want one; a path sorts naturally, survives
//! browsers that name their roots differently, and rebuilds into a tree on the
//! way back out.

use std::path::{Path, PathBuf};

/// One bookmark read out of a browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    pub title: String,
    pub url: String,
    /// Folder path, `/`-separated. Empty means the top of the bar.
    pub folder: String,
}

/// A browser profile holding a readable bookmark file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// What to show the user: "Brave — Default".
    pub label: String,
    pub path: PathBuf,
}

/// Chromium-family browsers, as (display name, path under the per-OS root).
///
/// Vivaldi and Opera are here because they are Chromium underneath and cost a
/// line each; a user who has one gets it for free, and a user who does not sees
/// nothing because the directory is absent.
#[cfg(target_os = "macos")]
const CHROMIUM_ROOTS: &[(&str, &str)] = &[
    ("Chrome", "Google/Chrome"),
    ("Brave", "BraveSoftware/Brave-Browser"),
    ("Edge", "Microsoft Edge"),
    ("Vivaldi", "Vivaldi"),
    ("Opera", "com.operasoftware.Opera"),
    ("Chromium", "Chromium"),
];

#[cfg(target_os = "linux")]
const CHROMIUM_ROOTS: &[(&str, &str)] = &[
    ("Chrome", "google-chrome"),
    ("Brave", "BraveSoftware/Brave-Browser"),
    ("Edge", "microsoft-edge"),
    ("Vivaldi", "vivaldi"),
    ("Opera", "opera"),
    ("Chromium", "chromium"),
];

#[cfg(target_os = "windows")]
const CHROMIUM_ROOTS: &[(&str, &str)] = &[
    ("Chrome", "Google/Chrome/User Data"),
    ("Brave", "BraveSoftware/Brave-Browser/User Data"),
    ("Edge", "Microsoft/Edge/User Data"),
    ("Vivaldi", "Vivaldi/User Data"),
    ("Opera", "Opera Software/Opera Stable"),
    ("Chromium", "Chromium/User Data"),
];

/// Where the per-user browser data directories live on this OS.
fn browser_data_root() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    {
        Some(home?.join("Library/Application Support"))
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home.map(|h| h.join(".config")))
    }
    #[cfg(target_os = "windows")]
    {
        let _ = home;
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    }
}

/// Every Chromium profile on this machine with a bookmark file.
///
/// A browser can hold many profiles ("Default", "Profile 1", a work profile),
/// and a person who keeps work and private bookmarks apart is exactly the
/// person asking for this feature — so every profile is offered separately
/// rather than silently merged.
pub fn discover() -> Vec<Source> {
    let Some(root) = browser_data_root() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, rel) in CHROMIUM_ROOTS {
        let base = root.join(rel);
        if !base.is_dir() {
            continue;
        }
        // The bookmark file sits directly in the profile directory, and the
        // profile directories sit directly in the browser's data directory.
        let Ok(entries) = std::fs::read_dir(&base) else {
            continue;
        };
        let mut found: Vec<Source> = Vec::new();
        for entry in entries.flatten() {
            let dir = entry.path();
            let file = dir.join("Bookmarks");
            if !file.is_file() {
                continue;
            }
            let profile = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            found.push(Source {
                label: format!("{name} — {profile}"),
                path: file,
            });
        }
        // Stable order so the list does not reshuffle between runs; readdir
        // order is not defined and a jumping list looks like a bug.
        found.sort_by(|a, b| a.label.cmp(&b.label));
        out.append(&mut found);
    }
    out
}

/// Read and flatten one Chromium `Bookmarks` file.
pub fn read_file(path: &Path) -> std::io::Result<Vec<Imported>> {
    let text = std::fs::read_to_string(path)?;
    Ok(parse(&text))
}

/// The pure half: JSON in, flat bookmarks out.
///
/// Malformed input yields an empty list rather than an error. This file is
/// written by a browser that may be running, and a half-written or unexpected
/// shape should mean "nothing to import from here", never a failed import of
/// every other profile in the same run.
pub fn parse(text: &str) -> Vec<Imported> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(roots) = doc.get("roots").and_then(|r| r.as_object()) else {
        return Vec::new();
    };

    // Chromium's own root keys. `bookmark_bar` is the visible bar and gets no
    // prefix, because prefixing every single bookmark with "Bookmarks bar/"
    // buys nothing. The others keep a name so they stay distinguishable.
    const ROOTS: &[(&str, &str)] = &[
        ("bookmark_bar", ""),
        ("other", "Other"),
        ("synced", "Mobile"),
    ];

    let mut out = Vec::new();
    for (key, prefix) in ROOTS {
        let Some(node) = roots.get(*key) else {
            continue;
        };
        // The root's OWN name is dropped, and its children are walked with the
        // prefix above. Walking the root node itself would fold its name into
        // every path below it, so every single bookmark on the bar would sit
        // under "Bookmarks bar/" — and in a browser localised to another
        // language, under whatever that is called there.
        let Some(children) = node.get("children").and_then(|c| c.as_array()) else {
            continue;
        };
        for child in children {
            walk(child, prefix, &mut out);
        }
    }
    out
}

/// Total bookmarks accepted from one file. A guard against a pathological or
/// hostile file, not a real limit: a very large personal collection is a few
/// thousand.
const MAX_BOOKMARKS: usize = 20_000;

/// Deepest folder nesting followed. Chromium itself has no limit, and the
/// recursion has to end somewhere that is not the stack.
const MAX_DEPTH: usize = 32;

fn walk(node: &serde_json::Value, folder: &str, out: &mut Vec<Imported>) {
    walk_at(node, folder, out, 0);
}

fn walk_at(node: &serde_json::Value, folder: &str, out: &mut Vec<Imported>, depth: usize) {
    if out.len() >= MAX_BOOKMARKS || depth > MAX_DEPTH {
        return;
    }
    match node.get("type").and_then(|t| t.as_str()) {
        Some("url") => {
            let url = node.get("url").and_then(|u| u.as_str()).unwrap_or("");
            // Chromium stores `javascript:` bookmarklets and internal
            // `chrome://` pages in the same tree. Neither survives being handed
            // to a different browser, and a bookmarklet is executable code we
            // have no business round-tripping.
            if !is_web_url(url) {
                return;
            }
            let title = node.get("name").and_then(|n| n.as_str()).unwrap_or("");
            out.push(Imported {
                // A bookmark with no name is legal and shows as its URL in the
                // browser; do the same rather than storing a blank row.
                title: if title.is_empty() {
                    url.to_string()
                } else {
                    title.to_string()
                },
                url: url.to_string(),
                folder: folder.to_string(),
            });
        }
        Some("folder") => {
            let name = node.get("name").and_then(|n| n.as_str()).unwrap_or("");
            // `/` is the path separator, so a folder literally named "a/b"
            // would otherwise read back as two levels.
            let safe = name.replace('/', "-");
            let child_folder = if folder.is_empty() {
                safe
            } else if safe.is_empty() {
                folder.to_string()
            } else {
                format!("{folder}/{safe}")
            };
            if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
                for child in children {
                    walk_at(child, &child_folder, out, depth + 1);
                }
            }
        }
        _ => {}
    }
}

/// Whether this is a URL worth carrying between browsers.
fn is_web_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "roots": {
        "bookmark_bar": {
          "type": "folder", "name": "Bookmarks bar",
          "children": [
            {"type": "url", "name": "Sybr", "url": "https://sybr.no"},
            {"type": "folder", "name": "Arbeid", "children": [
              {"type": "url", "name": "RMM", "url": "https://rmm.example/dash"},
              {"type": "folder", "name": "Kunder", "children": [
                {"type": "url", "name": "Laugstol", "url": "https://laugstol.no"}
              ]}
            ]}
          ]
        },
        "other": {
          "type": "folder", "name": "Other bookmarks",
          "children": [{"type": "url", "name": "Later", "url": "https://later.example"}]
        }
      }
    }"#;

    #[test]
    fn folders_become_paths_and_the_bar_is_not_prefixed() {
        let got = parse(SAMPLE);
        let find = |t: &str| got.iter().find(|b| b.title == t).cloned().unwrap();

        // The visible bar is the common case; prefixing every entry with
        // "Bookmarks bar/" would add a level to almost every path and mean
        // nothing.
        assert_eq!(find("Sybr").folder, "");
        assert_eq!(find("RMM").folder, "Arbeid");
        assert_eq!(find("Laugstol").folder, "Arbeid/Kunder");
        // The other roots keep a name so they stay apart from the bar.
        assert_eq!(find("Later").folder, "Other");
        assert_eq!(got.len(), 4);
    }

    #[test]
    fn bookmarklets_and_internal_pages_are_left_behind() {
        // A `javascript:` bookmark is executable code, and `chrome://` means
        // nothing in another browser. Carrying either between browsers is at
        // best useless and at worst running someone's old script somewhere new.
        let doc = r#"{"roots":{"bookmark_bar":{"type":"folder","name":"b","children":[
            {"type":"url","name":"evil","url":"javascript:alert(1)"},
            {"type":"url","name":"internal","url":"chrome://settings"},
            {"type":"url","name":"file","url":"file:///etc/passwd"},
            {"type":"url","name":"ok","url":"https://ok.example"}
        ]}}}"#;
        let got = parse(doc);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].url, "https://ok.example");
    }

    #[test]
    fn a_folder_named_with_a_slash_does_not_invent_a_level() {
        let doc = r#"{"roots":{"bookmark_bar":{"type":"folder","name":"b","children":[
            {"type":"folder","name":"AS/NO","children":[
                {"type":"url","name":"x","url":"https://x.example"}]}
        ]}}}"#;
        assert_eq!(parse(doc)[0].folder, "AS-NO");
    }

    #[test]
    fn an_unnamed_bookmark_falls_back_to_its_url() {
        let doc = r#"{"roots":{"bookmark_bar":{"type":"folder","name":"b","children":[
            {"type":"url","name":"","url":"https://nameless.example"}]}}}"#;
        assert_eq!(parse(doc)[0].title, "https://nameless.example");
    }

    #[test]
    fn junk_is_an_empty_list_not_a_panic() {
        // This file belongs to a browser that may be writing it right now.
        for body in [
            "",
            "not json",
            "{}",
            r#"{"roots":42}"#,
            r#"{"roots":{"bookmark_bar":7}}"#,
        ] {
            assert!(parse(body).is_empty(), "{body:?}");
        }
    }

    #[test]
    fn deep_nesting_terminates() {
        // Hand-built 100-deep tree: without the depth cap this recurses until
        // the stack ends, and a bookmark file is not a trusted input.
        let mut doc = r#"{"type":"url","name":"deep","url":"https://deep.example"}"#.to_string();
        for i in 0..100 {
            doc = format!(r#"{{"type":"folder","name":"f{i}","children":[{doc}]}}"#);
        }
        let full = format!(r#"{{"roots":{{"bookmark_bar":{doc}}}}}"#);
        // The point is that it returns at all.
        let got = parse(&full);
        assert!(got.len() <= 1);
    }
}
