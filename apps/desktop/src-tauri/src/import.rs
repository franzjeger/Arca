//! Reading what other password managers export.
//!
//! Three formats, told apart by content, never by file name:
//!
//! - **CSV**: browsers, Apple Passwords, and any header-mapped layout.
//! - **Bitwarden JSON** (unencrypted): logins with their authenticator keys,
//!   custom fields and extra addresses; secure notes; cards, identities and
//!   SSH keys.
//! - **1Password `.1pux`**: a zip whose `export.data` is JSON, with the same
//!   kinds of item.
//!
//! Nothing a file holds is dropped silently. What Arca has no item kind for
//! (cards, identities, licences) becomes a secure note listing every field.
//! What cannot be brought over at all is counted in [`LeftOut`] and shown to
//! the user: passkeys, whose private keys are not imported yet, and file
//! attachments.
//!
//! This module only parses. It never touches the vault, so every format is
//! tested from bytes alone.

use serde::Deserialize;
use serde_json::{Map, Value};
use std::io::Read;

/// The most a CSV or JSON export may take, and the most `export.data` may
/// inflate to. Real exports are a few megabytes; a zip can claim anything.
const MAX_EXPORT_BYTES: u64 = 64 * 1024 * 1024;

/// A login from an export. `totp` is raw (Base32 or `otpauth://`), normalized
/// later via `vault_core::edit::normalize_totp`.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct ParsedLogin {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub totp: String,
    pub notes: String,
}

/// A secure note, or an item Arca has no kind for, written out as one.
#[derive(Debug, PartialEq)]
pub(crate) struct ParsedNote {
    pub title: String,
    pub body: String,
}

/// What the export held that was not imported, so the user is told.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct LeftOut {
    pub passkeys: usize,
    pub attachments: usize,
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct Parsed {
    pub logins: Vec<ParsedLogin>,
    pub notes: Vec<ParsedNote>,
    /// Entries with nothing in them.
    pub skipped: usize,
    pub left_out: LeftOut,
}

#[derive(Debug, PartialEq)]
pub(crate) enum ImportError {
    /// The file could not be opened or read.
    Unreadable,
    /// Larger than any real export.
    TooLarge,
    /// A Bitwarden export that is encrypted or password protected.
    Encrypted,
    /// JSON or a zip, but not one of the exports above.
    Unrecognized,
}

impl ImportError {
    pub(crate) fn message(&self) -> &'static str {
        match self {
            Self::Unreadable => "Could not read the selected file.",
            Self::TooLarge => "That file is too large to be a password export.",
            Self::Encrypted => {
                "That Bitwarden export is encrypted. Export again as \".json\" (not \
                 \".json (Encrypted)\") and import that file."
            }
            Self::Unrecognized => {
                "That file is not an export Arca knows: a CSV, a Bitwarden .json or a \
                 1Password .1pux."
            }
        }
    }
}

/// Parse the export at `path`.
pub(crate) fn parse_file(path: &std::path::Path) -> Result<Parsed, ImportError> {
    let mut file = std::fs::File::open(path).map_err(|_| ImportError::Unreadable)?;
    let mut magic = [0u8; 4];
    let read = file.read(&mut magic).map_err(|_| ImportError::Unreadable)?;
    if magic[..read] == *b"PK\x03\x04" {
        // A .1pux carries the attachments too and can be large; only
        // `export.data` is read from it, and that is bounded.
        return parse_1pux(file);
    }
    let mut bytes = magic[..read].to_vec();
    file.take(MAX_EXPORT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ImportError::Unreadable)?;
    if bytes.len() as u64 > MAX_EXPORT_BYTES {
        return Err(ImportError::TooLarge);
    }
    parse_text(&bytes)
}

/// A CSV or JSON export, already in memory.
fn parse_text(bytes: &[u8]) -> Result<Parsed, ImportError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ImportError::Unreadable)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if text.trim_start().starts_with('{') {
        parse_bitwarden(text)
    } else {
        Ok(parse_logins_csv(text))
    }
}

// ---- shared helpers --------------------------------------------------------

/// Derive a title when the export has none: site host, else username, else a
/// generic label.
fn title_from(url: &str, username: &str) -> String {
    let host = url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .trim();
    if !host.is_empty() {
        host.to_string()
    } else if !username.is_empty() {
        username.to_string()
    } else {
        "Imported".to_string()
    }
}

fn text_of(value: &Option<String>) -> String {
    value.as_deref().unwrap_or("").trim().to_string()
}

/// The non-empty `parts`, a blank line between them.
fn paragraphs(parts: impl IntoIterator<Item = String>) -> String {
    parts
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// `label: value` lines for the pairs that have a value.
fn lines(pairs: impl IntoIterator<Item = (String, String)>) -> String {
    pairs
        .into_iter()
        .filter(|(_, value)| !value.trim().is_empty())
        .map(|(label, value)| {
            if label.trim().is_empty() {
                value
            } else {
                format!("{}: {value}", label.trim())
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The order people read these in. serde_json hands an object's members back
/// sorted by name, which puts a card's brand before its holder and a city
/// before its street. Members not listed follow, by name.
const READING_ORDER: &[&str] = &[
    // Bitwarden card
    "cardholderName",
    "brand",
    "number",
    "expMonth",
    "expYear",
    "code",
    // Bitwarden identity
    "title",
    "firstName",
    "middleName",
    "lastName",
    "company",
    "email",
    "phone",
    "username",
    "address1",
    "address2",
    "address3",
    // Addresses, Bitwarden's and 1Password's
    "street",
    "city",
    "state",
    "zip",
    "postalCode",
    "country",
    // Bitwarden SSH key
    "publicKey",
    "keyFingerprint",
    "privateKey",
];

/// An object's members in [`READING_ORDER`].
fn members(object: &Map<String, Value>) -> impl Iterator<Item = (&String, &Value)> {
    let rank = |key: &str| {
        READING_ORDER
            .iter()
            .position(|known| *known == key)
            .unwrap_or(READING_ORDER.len())
    };
    let mut members: Vec<_> = object.iter().collect();
    // Stable, so the unlisted keep the order serde_json gave them.
    members.sort_by_key(|(key, _)| rank(key));
    members.into_iter()
}

/// A JSON scalar as text; an object's members joined; nothing for null.
fn scalar(value: &Value) -> String {
    match value {
        Value::String(text) => text.trim().to_string(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Object(object) => members(object)
            .map(|(_, value)| scalar(value))
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join(", "),
        Value::Array(_) | Value::Null => String::new(),
    }
}

/// `cardholderName` as "Cardholder name".
fn label_of(key: &str) -> String {
    let mut label = String::with_capacity(key.len() + 4);
    for (index, ch) in key.chars().enumerate() {
        if index == 0 {
            label.extend(ch.to_uppercase());
        } else if ch.is_uppercase() {
            label.push(' ');
            label.extend(ch.to_lowercase());
        } else {
            label.push(ch);
        }
    }
    label
}

/// Every member of a JSON object that has a value, as `Label: value` lines.
fn object_lines(object: &Map<String, Value>) -> String {
    lines(members(object).map(|(key, value)| (label_of(key), scalar(value))))
}

/// A login, unless the entry holds nothing at all.
fn login_or_skip(parsed: &mut Parsed, mut login: ParsedLogin) {
    let empty = [&login.username, &login.password, &login.totp, &login.notes]
        .iter()
        .all(|field| field.is_empty());
    if empty && login.url.is_empty() {
        parsed.skipped += 1;
        return;
    }
    if login.title.is_empty() {
        login.title = title_from(&login.url, &login.username);
    }
    parsed.logins.push(login);
}

fn note_or_skip(parsed: &mut Parsed, title: String, body: String) {
    if title.is_empty() && body.is_empty() {
        parsed.skipped += 1;
    } else {
        parsed.notes.push(ParsedNote { title, body });
    }
}

// ---- CSV -------------------------------------------------------------------

/// Column indices discovered from the CSV header.
#[derive(Default)]
struct ColumnMap {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    totp: Option<usize>,
    notes: Option<usize>,
}

/// Parse a password-export CSV (Chrome/Brave/Edge, Apple Passwords, Firefox,
/// Bitwarden, and common generic layouts) by mapping header names
/// case-insensitively. Rows with neither a username nor a password are
/// counted as skipped.
pub(crate) fn parse_logins_csv(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(text.as_bytes());

    let headers = match reader.headers() {
        Ok(h) => h.clone(),
        Err(_) => return parsed,
    };

    let mut map = ColumnMap::default();
    for (i, h) in headers.iter().enumerate() {
        match h.trim().to_ascii_lowercase().as_str() {
            "title" | "name" => _ = map.title.get_or_insert(i),
            "url" | "urls" | "website" | "login_uri" | "loginuri" => _ = map.url.get_or_insert(i),
            "username" | "user" | "login" | "email" | "login_username" => {
                _ = map.username.get_or_insert(i)
            }
            "password" | "pwd" | "login_password" => _ = map.password.get_or_insert(i),
            "notes" | "note" | "comment" | "comments" => _ = map.notes.get_or_insert(i),
            "otpauth" | "otp" | "totp" | "otp_auth" | "totpauth" | "2fa" | "login_totp" => {
                _ = map.totp.get_or_insert(i)
            }
            _ => {}
        }
    }

    for record in reader.records().flatten() {
        let cell = |col: Option<usize>| -> String {
            col.and_then(|i| record.get(i))
                .unwrap_or("")
                .trim()
                .to_string()
        };
        let username = cell(map.username);
        let password = cell(map.password);
        if username.is_empty() && password.is_empty() {
            parsed.skipped += 1;
            continue;
        }
        let url = cell(map.url);
        let mut title = cell(map.title);
        if title.is_empty() {
            title = title_from(&url, &username);
        }
        parsed.logins.push(ParsedLogin {
            title,
            username,
            password,
            url,
            totp: cell(map.totp),
            notes: cell(map.notes),
        });
    }
    parsed
}

// ---- Bitwarden JSON --------------------------------------------------------

#[derive(Deserialize)]
struct BwExport {
    #[serde(default)]
    encrypted: bool,
    /// Absent in anything that is not a Bitwarden export.
    items: Option<Vec<BwItem>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwItem {
    /// 1 login, 2 secure note, 3 card, 4 identity, 5 SSH key.
    #[serde(rename = "type", default)]
    kind: u8,
    name: Option<String>,
    notes: Option<String>,
    #[serde(default)]
    fields: Option<Vec<BwField>>,
    login: Option<BwLogin>,
    card: Option<Map<String, Value>>,
    identity: Option<Map<String, Value>>,
    ssh_key: Option<Map<String, Value>>,
}

#[derive(Deserialize)]
struct BwField {
    name: Option<String>,
    value: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    #[serde(default)]
    uris: Option<Vec<BwUri>>,
    #[serde(default)]
    fido2_credentials: Option<Vec<Value>>,
}

#[derive(Deserialize)]
struct BwUri {
    uri: Option<String>,
}

fn parse_bitwarden(text: &str) -> Result<Parsed, ImportError> {
    let export: BwExport = serde_json::from_str(text).map_err(|_| ImportError::Unrecognized)?;
    if export.encrypted {
        return Err(ImportError::Encrypted);
    }
    let items = export.items.ok_or(ImportError::Unrecognized)?;

    let mut parsed = Parsed::default();
    for item in items {
        let title = text_of(&item.name);
        let custom = lines(
            item.fields
                .unwrap_or_default()
                .iter()
                .map(|field| (text_of(&field.name), text_of(&field.value))),
        );
        let notes = text_of(&item.notes);
        match (item.kind, item.login) {
            (1, Some(login)) => {
                parsed.left_out.passkeys += login.fido2_credentials.map_or(0, |keys| keys.len());
                let uris = login.uris.unwrap_or_default();
                let mut uris = uris
                    .iter()
                    .map(|uri| text_of(&uri.uri))
                    .filter(|uri| !uri.is_empty());
                let url = uris.next().unwrap_or_default();
                let also = lines(uris.map(|uri| ("Also used on".to_string(), uri)));
                login_or_skip(
                    &mut parsed,
                    ParsedLogin {
                        title,
                        username: text_of(&login.username),
                        password: text_of(&login.password),
                        url,
                        totp: text_of(&login.totp),
                        notes: paragraphs([notes, custom, also]),
                    },
                );
            }
            (kind, _) => {
                // A secure note is its text. A card, an identity or an SSH key
                // is its fields, which Arca keeps as a note rather than lose.
                let details = match kind {
                    3 => item.card,
                    4 => item.identity,
                    5 => item.ssh_key,
                    _ => None,
                };
                let details = details.as_ref().map(object_lines).unwrap_or_default();
                note_or_skip(&mut parsed, title, paragraphs([details, custom, notes]));
            }
        }
    }
    Ok(parsed)
}

// ---- 1Password .1pux -------------------------------------------------------

#[derive(Deserialize)]
struct OpExport {
    accounts: Vec<OpAccount>,
}

#[derive(Deserialize)]
struct OpAccount {
    #[serde(default)]
    vaults: Vec<OpVault>,
}

#[derive(Deserialize)]
struct OpVault {
    #[serde(default)]
    items: Vec<OpItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpItem {
    /// "001" login, "003" secure note, "005" password, "006" document; the
    /// rest (cards, identities, licences and so on) are fields and notes.
    #[serde(default)]
    category_uuid: String,
    #[serde(default)]
    overview: OpOverview,
    #[serde(default)]
    details: OpDetails,
}

#[derive(Deserialize, Default)]
struct OpOverview {
    title: Option<String>,
    url: Option<String>,
    #[serde(default)]
    urls: Option<Vec<OpUrl>>,
}

#[derive(Deserialize)]
struct OpUrl {
    url: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct OpDetails {
    #[serde(default)]
    login_fields: Option<Vec<OpLoginField>>,
    notes_plain: Option<String>,
    #[serde(default)]
    sections: Option<Vec<OpSection>>,
    /// The password of a "Password" item.
    password: Option<String>,
    document_attributes: Option<Value>,
}

#[derive(Deserialize)]
struct OpLoginField {
    value: Option<String>,
    designation: Option<String>,
}

#[derive(Deserialize)]
struct OpSection {
    title: Option<String>,
    #[serde(default)]
    fields: Option<Vec<OpField>>,
}

#[derive(Deserialize)]
struct OpField {
    title: Option<String>,
    /// One member, named for the field's type: `{"totp": "…"}`,
    /// `{"concealed": "…"}`, `{"address": {…}}`.
    #[serde(default)]
    value: Map<String, Value>,
}

fn parse_1pux(file: std::fs::File) -> Result<Parsed, ImportError> {
    let mut archive = zip::ZipArchive::new(file).map_err(|_| ImportError::Unrecognized)?;
    let data = archive
        .by_name("export.data")
        .map_err(|_| ImportError::Unrecognized)?;
    let mut json = Vec::new();
    data.take(MAX_EXPORT_BYTES + 1)
        .read_to_end(&mut json)
        .map_err(|_| ImportError::Unreadable)?;
    if json.len() as u64 > MAX_EXPORT_BYTES {
        return Err(ImportError::TooLarge);
    }
    parse_1password(&json)
}

fn parse_1password(json: &[u8]) -> Result<Parsed, ImportError> {
    let export: OpExport = serde_json::from_slice(json).map_err(|_| ImportError::Unrecognized)?;
    let mut parsed = Parsed::default();
    let items = export
        .accounts
        .into_iter()
        .flat_map(|account| account.vaults)
        .flat_map(|vault| vault.items);
    for item in items {
        let OpItem {
            category_uuid,
            overview,
            details,
        } = item;
        if category_uuid == "006" || details.document_attributes.is_some() {
            parsed.left_out.attachments += 1;
        }

        // Section fields: the first authenticator key is the login's; every
        // other field is kept as a line, under its section's title.
        let mut totp = String::new();
        let mut sections = Vec::new();
        for section in details.sections.unwrap_or_default() {
            let mut pairs = Vec::new();
            for field in section.fields.unwrap_or_default() {
                let Some((kind, value)) = field.value.iter().next() else {
                    continue;
                };
                let value = scalar(value);
                if kind == "totp" && totp.is_empty() && !value.is_empty() {
                    totp = value;
                } else {
                    pairs.push((text_of(&field.title), value));
                }
            }
            let body = lines(pairs);
            if !body.is_empty() {
                let heading = text_of(&section.title);
                sections.push(if heading.is_empty() {
                    body
                } else {
                    format!("{heading}\n{body}")
                });
            }
        }
        let fields = paragraphs(sections);
        let notes = text_of(&details.notes_plain);
        let title = text_of(&overview.title);

        if category_uuid != "001" && category_uuid != "005" {
            // A secure note leads with its text; anything else with its fields.
            let body = if category_uuid == "003" {
                paragraphs([notes, fields])
            } else {
                paragraphs([fields, notes])
            };
            // An authenticator key outside a login would otherwise vanish.
            let body = paragraphs([body, lines([("One-time password".to_string(), totp)])]);
            note_or_skip(&mut parsed, title, body);
            continue;
        }

        let designated = |wanted: &str| {
            details
                .login_fields
                .iter()
                .flatten()
                .find(|field| field.designation.as_deref() == Some(wanted))
                .map(|field| text_of(&field.value))
                .unwrap_or_default()
        };
        let mut password = designated("password");
        if password.is_empty() {
            password = text_of(&details.password);
        }
        let url = text_of(&overview.url);
        let urls = overview.urls.unwrap_or_default();
        let also = lines(
            urls.iter()
                .map(|entry| text_of(&entry.url))
                .filter(|other| !other.is_empty() && *other != url)
                .map(|other| ("Also used on".to_string(), other)),
        );
        login_or_skip(
            &mut parsed,
            ParsedLogin {
                title,
                username: designated("username"),
                password,
                url,
                totp,
                notes: paragraphs([notes, fields, also]),
            },
        );
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_chrome_csv() {
        let csv = "name,url,username,password,note\n\
                   GitHub,https://github.com,frank-lia,p4ss,my note\n\
                   ,https://x.com/login,user2,pw2,\n";
        let parsed = parse_logins_csv(csv);
        assert_eq!(parsed.skipped, 0);
        assert_eq!(parsed.logins.len(), 2);
        assert_eq!(parsed.logins[0].title, "GitHub");
        assert_eq!(parsed.logins[0].username, "frank-lia");
        assert_eq!(parsed.logins[0].notes, "my note");
        // No title column value -> derived from the URL host.
        assert_eq!(parsed.logins[1].title, "x.com");
    }

    #[test]
    fn parse_apple_csv_keeps_otpauth_and_skips_blank_rows() {
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
                   Bank,https://bank.com,me,secret,\"a, b\",otpauth://totp/Bank?secret=GEZDGNBVGY3TQOJQ\n\
                   ,,,,,\n";
        let parsed = parse_logins_csv(csv);
        assert_eq!(parsed.logins.len(), 1);
        assert_eq!(parsed.skipped, 1); // the empty row
        assert_eq!(parsed.logins[0].notes, "a, b"); // quoted comma preserved
        assert!(parsed.logins[0].totp.starts_with("otpauth://"));
    }

    /// A Bitwarden export with one of everything, laid out as Bitwarden's
    /// documentation gives it. Nulls are everywhere in real exports.
    const BITWARDEN: &str = r#"{
      "encrypted": false,
      "folders": [{"id": "f1", "name": "Work"}],
      "items": [
        {"type": 1, "name": "GitHub", "notes": "work account", "favorite": false,
         "fields": [{"name": "Recovery", "value": "abcd-efgh", "type": 0},
                    {"name": null, "value": null, "type": 0}],
         "login": {"uris": [{"match": null, "uri": "https://github.com/login"},
                            {"match": null, "uri": "https://gist.github.com"}],
                   "username": "frank", "password": "gh-pw",
                   "totp": "otpauth://totp/GitHub?secret=GEZDGNBVGY3TQOJQ",
                   "fido2Credentials": [{"credentialId": "x", "rpId": "github.com"}]}},
        {"type": 1, "name": "Bare", "notes": null, "fields": null,
         "login": {"uris": null, "username": null, "password": null, "totp": null}},
        {"type": 2, "name": "Wi-Fi at the cabin", "notes": "password is swordfish",
         "secureNote": {"type": 0}},
        {"type": 3, "name": "Visa", "notes": "debit",
         "card": {"cardholderName": "Frank Lia", "brand": "Visa", "number": "4111111111111111",
                  "expMonth": "12", "expYear": "2030", "code": "123"}},
        {"type": 4, "name": "Me", "notes": null,
         "identity": {"firstName": "Frank", "lastName": "Lia", "email": null, "ssn": "010101"}},
        {"type": 5, "name": "Server key", "notes": null,
         "sshKey": {"privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----", "publicKey": "ssh-ed25519 AAAA",
                    "keyFingerprint": "SHA256:abc"}}
      ]
    }"#;

    #[test]
    fn bitwarden_json_keeps_everything_an_item_holds() {
        let parsed = parse_text(BITWARDEN.as_bytes()).unwrap();

        assert_eq!(
            parsed.logins,
            [ParsedLogin {
                title: "GitHub".into(),
                username: "frank".into(),
                password: "gh-pw".into(),
                url: "https://github.com/login".into(),
                totp: "otpauth://totp/GitHub?secret=GEZDGNBVGY3TQOJQ".into(),
                notes:
                    "work account\n\nRecovery: abcd-efgh\n\nAlso used on: https://gist.github.com"
                        .into(),
            }]
        );
        // The login with nothing in it, not even an address.
        assert_eq!(parsed.skipped, 1);
        // Its passkey is not imported, and is reported rather than dropped.
        assert_eq!(
            parsed.left_out,
            LeftOut {
                passkeys: 1,
                attachments: 0
            }
        );

        let note = |title: &str| {
            &parsed
                .notes
                .iter()
                .find(|n| n.title == title)
                .unwrap_or_else(|| panic!("no note {title:?}"))
                .body
        };
        assert_eq!(note("Wi-Fi at the cabin"), "password is swordfish");
        assert_eq!(
            note("Visa"),
            "Cardholder name: Frank Lia\nBrand: Visa\nNumber: 4111111111111111\n\
             Exp month: 12\nExp year: 2030\nCode: 123\n\ndebit"
        );
        // A null member is not a line.
        assert_eq!(note("Me"), "First name: Frank\nLast name: Lia\nSsn: 010101");
        assert!(note("Server key").contains("Private key: -----BEGIN OPENSSH PRIVATE KEY-----"));
        assert_eq!(parsed.notes.len(), 4);
    }

    #[test]
    fn an_encrypted_or_foreign_json_file_is_refused_with_its_reason() {
        let encrypted = r#"{"encrypted": true, "passwordProtected": true, "data": "2.abc"}"#;
        assert_eq!(
            parse_text(encrypted.as_bytes()),
            Err(ImportError::Encrypted)
        );
        // Organization exports are encrypted the same way.
        let org = r#"{"encrypted": true, "items": []}"#;
        assert_eq!(parse_text(org.as_bytes()), Err(ImportError::Encrypted));
        for foreign in [r#"{"hello": "world"}"#, r#"{"items": 3}"#, "{ not json"] {
            assert_eq!(
                parse_text(foreign.as_bytes()),
                Err(ImportError::Unrecognized),
                "{foreign}"
            );
        }
        assert_eq!(
            parse_text(&[0xff, 0xfe, 0x00]),
            Err(ImportError::Unreadable)
        );
    }

    #[test]
    fn a_byte_order_mark_does_not_hide_the_format() {
        let json = format!("\u{feff}{BITWARDEN}");
        assert_eq!(parse_text(json.as_bytes()).unwrap().logins.len(), 1);
        let csv = "\u{feff}name,url,username,password\nA,https://a.example,me,pw\n";
        assert_eq!(parse_text(csv.as_bytes()).unwrap().logins[0].title, "A");
    }

    /// `export.data` as 1Password's documentation of the format lays it out.
    const ONEPASSWORD: &str = r#"{
      "accounts": [{
        "attrs": {"accountName": "Frank", "email": "frank@example.test"},
        "vaults": [{
          "attrs": {"name": "Personal"},
          "items": [
            {"uuid": "a", "state": "active", "categoryUuid": "001",
             "overview": {"title": "Dropbox", "url": "https://www.dropbox.com",
                          "urls": [{"label": "website", "url": "https://www.dropbox.com"},
                                   {"label": "", "url": "https://paper.dropbox.com"}]},
             "details": {
               "loginFields": [
                 {"value": "frank@example.test", "name": "email", "fieldType": "E", "designation": "username"},
                 {"value": "db-pw", "name": "password", "fieldType": "P", "designation": "password"},
                 {"value": "on", "name": "remember", "fieldType": "C", "designation": ""}],
               "notesPlain": "shared with family",
               "sections": [
                 {"title": "", "name": "Section_1", "fields": [
                   {"title": "one-time password", "id": "TOTP_1", "value": {"totp": "GEZDGNBVGY3TQOJQ"}}]},
                 {"title": "Recovery", "name": "Section_2", "fields": [
                   {"title": "backup code", "id": "x", "value": {"concealed": "1234-5678"}},
                   {"title": "empty", "id": "y", "value": {"string": ""}}]}]}},
            {"uuid": "b", "state": "archived", "categoryUuid": "005",
             "overview": {"title": "Router"}, "details": {"password": "admin-pw"}},
            {"uuid": "c", "categoryUuid": "003",
             "overview": {"title": "Gate code"}, "details": {"notesPlain": "4711"}},
            {"uuid": "d", "categoryUuid": "002",
             "overview": {"title": "Mastercard"},
             "details": {"notesPlain": "travel card", "sections": [{"title": "", "fields": [
               {"title": "cardholder name", "value": {"string": "Frank Lia"}},
               {"title": "number", "value": {"creditCardNumber": "5555555555554444"}},
               {"title": "expiry date", "value": {"monthYear": 203012}},
               {"title": "billing address", "value": {"address": {"street": "Storgata 1", "city": "Skien", "zip": ""}}}]}]}},
            {"uuid": "e", "categoryUuid": "006",
             "overview": {"title": "Passport scan"},
             "details": {"documentAttributes": {"fileName": "passport.pdf", "documentId": "z"}}},
            {"uuid": "f", "categoryUuid": "001", "overview": {}, "details": {}}
          ]}]}]}"#;

    #[test]
    fn onepassword_export_keeps_everything_an_item_holds() {
        let parsed = parse_1password(ONEPASSWORD.as_bytes()).unwrap();

        assert_eq!(
            parsed.logins,
            [
                ParsedLogin {
                    title: "Dropbox".into(),
                    username: "frank@example.test".into(),
                    password: "db-pw".into(),
                    url: "https://www.dropbox.com".into(),
                    totp: "GEZDGNBVGY3TQOJQ".into(),
                    notes: "shared with family\n\nRecovery\nbackup code: 1234-5678\n\n\
                            Also used on: https://paper.dropbox.com"
                        .into(),
                },
                // A "Password" item, archived: still the user's, still imported.
                ParsedLogin {
                    title: "Router".into(),
                    password: "admin-pw".into(),
                    ..ParsedLogin::default()
                },
            ]
        );
        assert_eq!(
            parsed.notes,
            [
                ParsedNote {
                    title: "Gate code".into(),
                    body: "4711".into()
                },
                ParsedNote {
                    title: "Mastercard".into(),
                    body: "cardholder name: Frank Lia\nnumber: 5555555555554444\n\
                           expiry date: 203012\nbilling address: Storgata 1, Skien\n\ntravel card"
                        .into(),
                },
                // The document's file is not imported; its entry is kept.
                ParsedNote {
                    title: "Passport scan".into(),
                    body: String::new()
                },
            ]
        );
        assert_eq!(
            parsed.left_out,
            LeftOut {
                passkeys: 0,
                attachments: 1
            }
        );
        assert_eq!(parsed.skipped, 1);
    }

    fn zip_with(name: &str, contents: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let mut zip = zip::ZipWriter::new(file.as_file_mut());
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file(name, options).unwrap();
        zip.write_all(contents).unwrap();
        zip.finish().unwrap();
        file
    }

    #[test]
    fn a_1pux_file_is_recognized_by_its_content_whatever_it_is_called() {
        let export = zip_with("export.data", ONEPASSWORD.as_bytes());
        let parsed = parse_file(export.path()).unwrap();
        assert_eq!(parsed.logins.len(), 2);
        assert_eq!(parsed.notes.len(), 3);

        // Some other zip, and a zip whose export.data is something else.
        let other = zip_with("readme.txt", b"hello");
        assert_eq!(parse_file(other.path()), Err(ImportError::Unrecognized));
        let wrong = zip_with("export.data", br#"{"accounts": 3}"#);
        assert_eq!(parse_file(wrong.path()), Err(ImportError::Unrecognized));
    }

    #[test]
    fn an_export_data_that_inflates_past_the_limit_is_refused() {
        // 65 MiB of spaces deflates to a few kilobytes: what a zip bomb is.
        let bomb = zip_with(
            "export.data",
            &vec![b' '; (MAX_EXPORT_BYTES + 1024 * 1024) as usize],
        );
        assert!(bomb.as_file().metadata().unwrap().len() < 1024 * 1024);
        assert_eq!(parse_file(bomb.path()), Err(ImportError::TooLarge));
    }

    #[test]
    fn text_exports_are_read_from_disk_and_missing_files_say_so() {
        let mut json = tempfile::NamedTempFile::new().unwrap();
        json.write_all(BITWARDEN.as_bytes()).unwrap();
        assert_eq!(parse_file(json.path()).unwrap().notes.len(), 4);

        let mut tiny = tempfile::NamedTempFile::new().unwrap();
        tiny.write_all(b"a,b").unwrap();
        assert_eq!(parse_file(tiny.path()).unwrap(), Parsed::default());
        assert_eq!(
            parse_file(std::path::Path::new("/nonexistent/export.csv")),
            Err(ImportError::Unreadable)
        );
    }
}
