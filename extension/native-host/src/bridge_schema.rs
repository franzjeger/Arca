use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct BookmarkWire {
    pub title: String,
    pub url: String,
    #[serde(default)]
    pub folder: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BridgeRequest {
    Hello {
        token: String,
        #[serde(default)]
        protocol: Option<u32>,
        #[serde(default)]
        nonce: Option<String>,
    },
    Match {
        url: String,
    },
    Fill {
        id: String,
        url: String,
    },
    PasskeyCreate {
        origin: String,
        rp_id: String,
        #[serde(default)]
        user_name: String,
        #[serde(default)]
        user_handle: Vec<u8>,
        #[serde(default)]
        exclude_credentials: Vec<Vec<u8>>,
    },
    PasskeyGet {
        origin: String,
        rp_id: String,
        client_data_hash: Vec<u8>,
        #[serde(default)]
        allow_credentials: Vec<Vec<u8>>,
        /// Chosen in Arca's in-page picker; the app treats it as the approval.
        #[serde(default)]
        picked: bool,
    },
    SaveProbe {
        url: String,
        #[serde(default)]
        username: String,
        password: String,
    },
    ImportBookmarks {
        items: Vec<BookmarkWire>,
    },
    ListBookmarks,
    SaveLogin {
        url: String,
        #[serde(default)]
        username: String,
        password: String,
    },
    #[serde(rename = "request_unlock")]
    Unlock,
    GeneratePassword {
        #[serde(default)]
        length: Option<usize>,
        #[serde(default)]
        symbols: Option<bool>,
    },
    CreateLogin {
        title: String,
        #[serde(default)]
        username: String,
        #[serde(default)]
        url: String,
        #[serde(default)]
        notes: String,
        #[serde(default)]
        length: Option<usize>,
        #[serde(default)]
        symbols: Option<bool>,
        #[serde(default)]
        reveal: bool,
    },
    DeleteItem {
        id: String,
    },
    DeleteBookmarks {
        #[serde(default)]
        url: String,
        #[serde(default)]
        folder: String,
    },
    ReadPassword {
        id: String,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BridgeResponse {
    Ok {
        protocol: u32,
        version: String,
        build: String,
        commit: String,
        pid: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        proof: Option<String>,
    },
    Logins {
        items: Vec<BridgeLoginMatch>,
    },
    Credentials {
        username: String,
        password: String,
    },
    PasskeyCredential {
        credential_id: Vec<u8>,
        attestation_object: Vec<u8>,
    },
    PasskeyAssertion {
        credential_id: Vec<u8>,
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
        user_handle: Vec<u8>,
    },
    SaveDecision {
        action: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
    },
    Saved,
    CreatedLogin {
        id: String,
        title: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    Password {
        password: String,
    },
    Deleted {
        id: String,
        title: String,
    },
    ImportedBookmarks {
        added: usize,
    },
    UnlockRequested,
    Bookmarks {
        items: Vec<BookmarkWire>,
    },
    DeletedBookmarks {
        removed: u64,
    },
    GeneratedPassword {
        password: String,
    },
    Error {
        message: String,
    },
}

// Desktop summaries do not contain a URL. The native host attaches the
// requesting page URL when constructing the browser response.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct BridgeLoginMatch {
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_id: Vec<u8>,
    pub title: String,
    pub username: String,
    #[serde(default = "default_kind")]
    pub kind: String,
}

pub(super) fn default_kind() -> String {
    "password".to_string()
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;

    #[test]
    fn desktop_summary_without_url_is_valid() {
        let response: BridgeResponse = serde_json::from_str(
            r#"{"type":"logins","items":[{"id":"test","title":"Example","username":"user","kind":"password"}]}"#
        ).unwrap();
        assert!(matches!(response, BridgeResponse::Logins { items } if items.len() == 1));
    }

    #[test]
    fn incomplete_desktop_summary_is_rejected() {
        assert!(serde_json::from_str::<BridgeResponse>(
            r#"{"type":"logins","items":[{"id":"test","title":"Example"}]}"#
        )
        .is_err());
    }
}
