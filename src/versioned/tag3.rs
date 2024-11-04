use crate::types::{
    DelegationConditions, EventKind, Id, NAddr, PublicKey, Signature, UncheckedUrl,
};
use crate::Error;
use serde::{Deserialize, Serialize};
#[cfg(feature = "speedy")]
use speedy::{Readable, Writable};

/// A tag on an Event
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct TagV3(Vec<String>);

impl TagV3 {
    const EMPTY_STRING: &'static str = "";

    /// Create a new tag
    pub fn new(fields: &[&str]) -> TagV3 {
        TagV3(fields.iter().map(|f| (*f).to_owned()).collect())
    }

    /// Create a new tag without copying
    pub fn from_strings(fields: Vec<String>) -> TagV3 {
        TagV3(fields)
    }

    /// Remove empty fields from the end
    pub fn trim(&mut self) {
        while self.0[self.len() - 1].is_empty() {
            let _ = self.0.pop();
        }
    }

    /// Into a `Vec<String>`
    pub fn into_inner(self) -> Vec<String> {
        self.0
    }

    /// Number of string fields in the tag
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Get the string at the given index
    pub fn get_index(&self, index: usize) -> &str {
        if self.len() > index {
            &self.0[index]
        } else {
            Self::EMPTY_STRING
        }
    }

    /// Set the string at the given index
    pub fn set_index(&mut self, index: usize, value: String) {
        while self.len() <= index {
            self.0.push("".to_owned());
        }
        self.0[index] = value;
    }

    /// Push another values onto the tag
    pub fn push_value(&mut self, value: String) {
        self.0.push(value);
    }

    /// Push more values onto the tag
    pub fn push_values(&mut self, mut values: Vec<String>) {
        for value in values.drain(..) {
            self.0.push(value);
        }
    }

    /// Get the tag name for the tag (the first string in the array)
    pub fn tagname(&self) -> &str {
        self.get_index(0)
    }

    /// Get the tag value (index 1, after the tag name)
    pub fn value(&self) -> &str {
        self.get_index(1)
    }

    /// Get the marker (if relevant), else ""
    pub fn marker(&self) -> &str {
        if self.tagname() == "e" {
            self.get_index(3)
        } else if self.tagname() == "a" {
            self.get_index(2)
        } else {
            Self::EMPTY_STRING
        }
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> TagV3 {
        TagV3(vec!["e".to_string(), UncheckedUrl::mock().0])
    }

    /// Create a new 'a' address tag
    pub fn new_address(naddr: &NAddr, marker: Option<String>) -> TagV3 {
        let mut vec = vec![
            "a".to_owned(),
            format!(
                "{}:{}:{}",
                Into::<u32>::into(naddr.kind),
                naddr.author.as_hex_string(),
                naddr.d
            ),
        ];

        if !naddr.relays.is_empty() {
            vec.push(naddr.relays[0].0.clone());
        } else if marker.is_some() {
            vec.push("".to_owned());
        }

        if let Some(marker) = marker {
            vec.push(marker);
        }
        TagV3(vec)
    }

    /// Parse an 'a' tag
    /// `['a', 'kind:pubkeyhex:d', <optrelay>, <optmarker>]`
    pub fn parse_address(&self) -> Result<(NAddr, Option<String>), Error> {
        let strings = &self.0;

        if strings.len() < 2 {
            return Err(Error::TagMismatch);
        }
        if &strings[0] != "a" {
            return Err(Error::TagMismatch);
        }

        let (kind, author, d) = {
            let parts: Vec<&str> = strings[1].split(':').collect();
            if parts.len() < 3 {
                return Err(Error::TagMismatch);
            }
            let kind: EventKind = {
                let kindnum: u32 = parts[0].parse::<u32>()?;
                From::from(kindnum)
            };
            if !kind.is_replaceable() {
                return Err(Error::NonReplaceableAddr);
            }
            let author: PublicKey = PublicKey::try_from_hex_string(parts[1], true)?;
            let d = parts[2].to_string();
            (kind, author, d)
        };

        let relays: Vec<UncheckedUrl> = if strings.len() > 2 {
            vec![UncheckedUrl(strings[2].clone())]
        } else {
            vec![]
        };

        let na = NAddr {
            d,
            relays,
            kind,
            author,
        };

        let marker = if strings.len() >= 4 {
            Some(strings[3].clone())
        } else {
            None
        };

        Ok((na, marker))
    }

    /// Create a "content-warning" tag
    pub fn new_content_warning(warning: &str) -> TagV3 {
        TagV3(vec!["content-warning".to_string(), warning.to_string()])
    }

    /// Parse a "content-warning" tag
    pub fn parse_content_warning(&self) -> Result<Option<String>, Error> {
        if self.0.is_empty() {
            return Err(Error::TagMismatch);
        }
        if &self.0[0] != "content-warning" {
            return Err(Error::TagMismatch);
        }
        if self.len() >= 2 {
            Ok(Some(self.0[1].to_string()))
        } else {
            Ok(None)
        }
    }

    /// Create an "e" tag
    pub fn new_event(
        id: Id,
        recommended_relay_url: Option<UncheckedUrl>,
        marker: Option<String>,
        pubkey: Option<PublicKey>,
    ) -> TagV3 {
        let mut v: Vec<String> = vec!["e".to_owned(), id.as_hex_string()];

        if let Some(rurl) = recommended_relay_url {
            v.push(rurl.0);
        } else if marker.is_some() || pubkey.is_some() {
            v.push("".to_owned());
        }

        if let Some(mark) = marker {
            v.push(mark);
        } else if pubkey.is_some() {
            v.push("".to_owned());
        }

        if let Some(pk) = pubkey {
            v.push(pk.as_hex_string());
        }

        TagV3(v)
    }

    /// Parse an "e" tag
    /// `['e', <id>, <rurl>, <marker>]`
    pub fn parse_event(
        &self,
    ) -> Result<(Id, Option<UncheckedUrl>, Option<String>, Option<PublicKey>), Error> {
        if self.len() < 2 {
            return Err(Error::TagMismatch);
        }
        if &self.0[0] != "e" {
            return Err(Error::TagMismatch);
        }
        let id = Id::try_from_hex_string(&self.0[1])?;

        let url = if self.len() >= 3 {
            if self.0[2].len() > 0 {
                Some(UncheckedUrl(self.0[2].to_owned()))
            } else {
                None
            }
        } else {
            None
        };

        let marker = if self.len() >= 4 {
            if self.0[3].len() > 0 {
                Some(self.0[3].to_owned())
            } else {
                None
            }
        } else {
            None
        };

        let pk = if self.len() >= 5 {
            if let Ok(pk) = PublicKey::try_from_hex_string(&self.0[4], true) {
                Some(pk)
            } else {
                None
            }
        } else {
            None
        };

        Ok((id, url, marker, pk))
    }

    /// Create a "q" tag
    pub fn new_quote(
        id: Id,
        recommended_relay_url: Option<UncheckedUrl>,
        pubkey: Option<PublicKey>,
    ) -> TagV3 {
        let mut v: Vec<String> = vec!["q".to_owned(), id.as_hex_string()];

        if let Some(rurl) = recommended_relay_url {
            v.push(rurl.0);
        } else if pubkey.is_some() {
            v.push("".to_owned());
        }

        if let Some(pk) = pubkey {
            v.push(pk.as_hex_string());
        }

        TagV3(v)
    }

    /// Parse a "q" tag
    pub fn parse_quote(&self) -> Result<(Id, Option<UncheckedUrl>, Option<PublicKey>), Error> {
        if self.len() < 2 {
            return Err(Error::TagMismatch);
        }
        if &self.0[0] != "q" {
            return Err(Error::TagMismatch);
        }
        let id = Id::try_from_hex_string(&self.0[1])?;

        let url = if self.len() >= 3 {
            if self.0[2].len() > 0 {
                Some(UncheckedUrl(self.0[2].to_owned()))
            } else {
                None
            }
        } else {
            None
        };

        let pubkey = if self.len() >= 4 {
            if let Ok(pk) = PublicKey::try_from_hex_string(&self.0[3], true) {
                Some(pk)
            } else {
                None
            }
        } else {
            None
        };

        Ok((id, url, pubkey))
    }

    /// Create a "p" tag
    pub fn new_pubkey(
        pubkey: PublicKey,
        relay_url: Option<UncheckedUrl>,
        petname: Option<String>,
    ) -> TagV3 {
        let mut v: Vec<String> = vec!["p".to_owned(), pubkey.as_hex_string()];
        if let Some(rurl) = relay_url {
            v.push(rurl.0);
        } else if petname.is_some() {
            v.push("".to_owned())
        }
        if let Some(pet) = petname {
            v.push(pet);
        }
        TagV3(v)
    }

    /// Parse a "p" tag
    pub fn parse_pubkey(&self) -> Result<(PublicKey, Option<UncheckedUrl>, Option<String>), Error> {
        if self.len() < 2 {
            return Err(Error::TagMismatch);
        }
        if &self.0[0] != "p" {
            return Err(Error::TagMismatch);
        }
        let pubkey = PublicKey::try_from_hex_string(&self.0[1], true)?;
        let url = if self.len() >= 3 {
            Some(UncheckedUrl(self.0[2].to_owned()))
        } else {
            None
        };
        let petname = if self.len() >= 4 {
            if self.0[3].is_empty() {
                None
            } else {
                Some(self.0[3].to_owned())
            }
        } else {
            None
        };
        Ok((pubkey, url, petname))
    }

    /// Create a "t" tag
    pub fn new_hashtag(hashtag: String) -> TagV3 {
        TagV3(vec!["t".to_string(), hashtag])
    }

    /// Parse an "t" tag
    pub fn parse_hashtag(&self) -> Result<String, Error> {
        if self.len() < 2 {
            return Err(Error::TagMismatch);
        }
        if &self.0[0] != "t" {
            return Err(Error::TagMismatch);
        }
        Ok(self.0[1].to_string())
    }

    /// Create an "r" tag
    pub fn new_relay(url: UncheckedUrl, usage: Option<String>) -> TagV3 {
        let mut v = vec!["r".to_owned(), url.0];
        if let Some(u) = usage {
            v.push(u)
        }
        TagV3(v)
    }

    /// Parse an "r" tag
    pub fn parse_relay(&self) -> Result<(UncheckedUrl, Option<String>), Error> {
        if self.len() < 2 {
            return Err(Error::TagMismatch);
        }
        if &self.0[0] != "r" {
            return Err(Error::TagMismatch);
        }
        let relay = UncheckedUrl(self.0[1].clone());
        let marker = if self.len() >= 3 {
            Some(self.0[2].clone())
        } else {
            None
        };
        Ok((relay, marker))
    }

    /// Create a "d" tag
    pub fn new_identifier(identifier: String) -> TagV3 {
        TagV3(vec!["d".to_string(), identifier])
    }

    /// Parse a "d" tag
    pub fn parse_identifier(&self) -> Result<String, Error> {
        if self.len() < 2 {
            return Err(Error::TagMismatch);
        }
        if &self.0[0] != "d" {
            return Err(Error::TagMismatch);
        }
        Ok(self.0[1].to_string())
    }

    /// Create a "subject" tag
    pub fn new_subject(subject: String) -> TagV3 {
        TagV3(vec!["subject".to_string(), subject])
    }

    /// Parse a "subject" tag
    pub fn parse_subject(&self) -> Result<String, Error> {
        if self.len() < 2 {
            return Err(Error::TagMismatch);
        }
        if &self.0[0] != "subject" {
            return Err(Error::TagMismatch);
        }
        Ok(self.0[1].to_string())
    }

    /// Create a "nonce" tag
    pub fn new_nonce(nonce: u32, target: Option<u32>) -> TagV3 {
        let mut v = vec!["nonce".to_owned(), format!("{}", nonce)];
        if let Some(targ) = target {
            v.push(format!("{}", targ));
        }
        TagV3(v)
    }

    /// Parse a "nonce" tag
    pub fn parse_nonce(&self) -> Result<(u64, Option<u32>), Error> {
        if self.len() < 2 {
            return Err(Error::TagMismatch);
        }
        if &self.0[0] != "nonce" {
            return Err(Error::TagMismatch);
        }
        let nonce = self.0[1].parse::<u64>()?;
        let target = if self.len() >= 3 {
            Some(self.0[2].parse::<u32>()?)
        } else {
            None
        };
        Ok((nonce, target))
    }

    /// Create a "title" tag
    pub fn new_title(title: String) -> TagV3 {
        TagV3(vec!["title".to_string(), title])
    }

    /// Parse a "title" tag
    pub fn parse_title(&self) -> Result<String, Error> {
        if self.len() < 2 {
            return Err(Error::TagMismatch);
        }
        if &self.0[0] != "title" {
            return Err(Error::TagMismatch);
        }
        Ok(self.0[1].to_string())
    }

    /// Create a "summary" tag
    pub fn new_summary(summary: String) -> TagV3 {
        TagV3(vec!["summary".to_string(), summary])
    }

    /// Parse a "summary" tag
    pub fn parse_summary(&self) -> Result<String, Error> {
        if self.len() < 2 {
            return Err(Error::TagMismatch);
        }
        if &self.0[0] != "summary" {
            return Err(Error::TagMismatch);
        }
        Ok(self.0[1].to_string())
    }

    /// Create a "k" tag
    pub fn new_kind(kind: EventKind) -> TagV3 {
        TagV3(vec!["k".to_owned(), format!("{}", Into::<u32>::into(kind))])
    }

    /// Parse a "k" tag
    pub fn parse_kind(&self) -> Result<EventKind, Error> {
        if self.len() < 2 {
            return Err(Error::TagMismatch);
        }
        if &self.0[0] != "k" {
            return Err(Error::TagMismatch);
        }
        let u = self.0[1].parse::<u32>()?;
        Ok(u.into())
    }

    /// New delegation tag
    pub fn new_delegation(
        pubkey: PublicKey,
        conditions: DelegationConditions,
        sig: Signature,
    ) -> TagV3 {
        TagV3(vec![
            "delegation".to_owned(),
            pubkey.as_hex_string(),
            conditions.as_string(),
            sig.as_hex_string(),
        ])
    }

    /// parse delegation tag
    pub fn parse_delegation(&self) -> Result<(PublicKey, DelegationConditions, Signature), Error> {
        if self.len() < 4 {
            return Err(Error::TagMismatch);
        }
        if &self.0[0] != "delegation" {
            return Err(Error::TagMismatch);
        }
        let pk = PublicKey::try_from_hex_string(&self.0[1], true)?;
        let conditions = DelegationConditions::try_from_str(&self.0[2])?;
        let sig = Signature::try_from_hex_string(&self.0[3])?;
        Ok((pk, conditions, sig))
    }

    /// New proxy tag
    pub fn proxy(protocol: String, id: String) -> TagV3 {
        TagV3(vec!["proxy".to_owned(), protocol, id])
    }

    /// parse proxy tag
    pub fn parse_proxy(&self) -> Result<(String, String), Error> {
        if self.len() < 3 {
            return Err(Error::TagMismatch);
        }
        if &self.0[0] != "proxy" {
            return Err(Error::TagMismatch);
        }
        let protocol = self.0[1].to_owned();
        let id = self.0[2].to_owned();
        Ok((protocol, id))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {TagV3, test_tag_serde}

    #[test]
    fn test_a_tag() {
        let na = NAddr {
            d: "blog-20231029".to_owned(),
            relays: vec![UncheckedUrl("badurl".to_owned())],
            kind: EventKind::LongFormContent,
            author: PublicKey::mock_deterministic(),
        };

        let tag = TagV3::new_address(&na, None);
        let (na2, _optmarker) = tag.parse_address().unwrap();
        // Equal only because there is just 1 UncheckedUrl, else might have dropped
        // the rest
        assert_eq!(na, na2);

        // Test a known JSON a tag:
        let json =
            r#"["a","34550:d0debf9fb12def81f43d7c69429bb784812ac1e4d2d53a202db6aac7ea4b466c:git"]"#;
        let tag: TagV3 = serde_json::from_str(&json).unwrap();
        assert!(tag.parse_address().is_ok());

        let tag = TagV3::new(&[
            "a",
            "30023:b12b632c887f0c871d140d37bcb6e7c1e1a80264d0b7de8255aa1951d9e1ff79:1716928135712",
            "",
            "root",
        ]);
        let (_, marker) = tag.parse_address().unwrap();
        assert!(marker.as_deref().unwrap() == "root");
    }

    #[test]
    fn test_content_warning_tag() {
        let tag = TagV3::new(&["content-warning"]);
        assert_eq!(tag.parse_content_warning().unwrap(), None);

        let tag = TagV3::new_content_warning("danger");
        assert_eq!(
            tag.parse_content_warning().unwrap(),
            Some("danger".to_owned())
        );

        let tag = TagV3::new(&["dummy", "tag"]);
        assert!(tag.parse_content_warning().is_err());
    }

    #[test]
    fn test_event_tag() {
        let tag = TagV3::new_event(Id::mock(), None, None, None);
        assert_eq!(tag.parse_event().unwrap(), (Id::mock(), None, None, None));

        let data = (
            Id::mock(),
            Some(UncheckedUrl("dummy".to_owned())),
            Some("foo".to_owned()),
            None,
        );
        let tag = TagV3::new_event(data.0, data.1.clone(), data.2.clone(), data.3.clone());
        assert_eq!(tag.parse_event().unwrap(), data);

        let tag = TagV3(vec![
            "e".to_string(),
            "7760408f6459b9546c3a4e70e3e56756421fba34526b7d460db3fcfd2f8817db".to_string(),
            "wss://chorus.example".to_string(),
            "".to_string(),
            "460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c".to_string(),
        ]);
        let tag_data = tag.parse_event().unwrap();
        assert!(tag_data.1.is_some());
        assert!(tag_data.2.is_none());
        assert_eq!(
            tag_data.3,
            Some(
                PublicKey::try_from_hex_string(
                    "460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c",
                    false
                )
                .unwrap()
            )
        );

        let tag2 = TagV3::new_event(
            Id::try_from_hex_string(
                "7760408f6459b9546c3a4e70e3e56756421fba34526b7d460db3fcfd2f8817db",
            )
            .unwrap(),
            Some(UncheckedUrl("wss://chorus.example".to_string())),
            None,
            Some(
                PublicKey::try_from_hex_string(
                    "460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c",
                    false,
                )
                .unwrap(),
            ),
        );

        assert_eq!(tag, tag2);
    }

    #[test]
    fn test_quote_tag() {
        let id = Id::mock();
        let pk = PublicKey::mock();

        let tag1 = TagV3::new_quote(id, None, Some(pk));
        let (id2, opturl, optpk) = tag1.parse_quote().unwrap();

        assert_eq!(id, id2);
        assert!(opturl.is_none());
        assert_eq!(Some(pk), optpk);
    }

    #[test]
    fn test_pubkey_tag() {
        let tag = TagV3::new_pubkey(PublicKey::mock_deterministic(), None, None);
        assert_eq!(
            tag.parse_pubkey().unwrap(),
            (PublicKey::mock_deterministic(), None, None)
        );

        let data = (
            PublicKey::mock(),
            Some(UncheckedUrl("dummy".to_owned())),
            Some("foo".to_owned()),
        );
        let tag = TagV3::new_pubkey(data.0, data.1.clone(), data.2.clone());
        assert_eq!(tag.parse_pubkey().unwrap(), data);
    }

    #[test]
    fn test_hashtag_tag() {
        let tag = TagV3::new(&["t"]);
        assert!(tag.parse_hashtag().is_err());

        let tag = TagV3::new_hashtag("footstr".to_owned());
        assert_eq!(tag.parse_hashtag().unwrap(), "footstr".to_owned());

        let tag = TagV3::new(&["dummy", "tag"]);
        assert!(tag.parse_hashtag().is_err());
    }

    #[test]
    fn test_relay_tag() {
        let tag = TagV3::new(&["r", "wss://example.com", "read"]);
        let parsed = tag.parse_relay().unwrap();
        let data = (
            UncheckedUrl("wss://example.com".to_owned()),
            Some("read".to_owned()),
        );
        assert_eq!(parsed, data);

        let tag2 = TagV3::new_relay(data.0, data.1);
        assert_eq!(tag, tag2);
    }

    #[test]
    fn test_identifier_tag() {
        let tag = TagV3::new(&["d"]);
        assert!(tag.parse_identifier().is_err());

        let tag = TagV3::new_identifier("myblog123".to_owned());
        assert_eq!(tag.parse_identifier().unwrap(), "myblog123".to_owned());

        let tag = TagV3::new(&["dummy", "tag"]);
        assert!(tag.parse_identifier().is_err());
    }

    #[test]
    fn test_subject_tag() {
        let tag = TagV3::new(&["subject"]);
        assert!(tag.parse_subject().is_err());

        let tag = TagV3::new_subject("Attn: Nurses".to_owned());
        assert_eq!(tag.parse_subject().unwrap(), "Attn: Nurses".to_owned());

        let tag = TagV3::new(&["dummy", "tag"]);
        assert!(tag.parse_subject().is_err());
    }

    #[test]
    fn test_nonce_tag() {
        let tag = TagV3::new(&["nonce"]);
        assert!(tag.parse_nonce().is_err());

        let tag = TagV3::new_nonce(132345, Some(20));
        assert_eq!(tag.parse_nonce().unwrap(), (132345, Some(20)));

        let tag = TagV3::new_nonce(132345, None);
        assert_eq!(tag.parse_nonce().unwrap(), (132345, None));

        let tag = TagV3::new(&["dummy", "tag"]);
        assert!(tag.parse_nonce().is_err());
    }

    #[test]
    fn test_title_tag() {
        let tag = TagV3::new(&["title"]);
        assert!(tag.parse_title().is_err());

        let tag = TagV3::new_title("Attn: Nurses".to_owned());
        assert_eq!(tag.parse_title().unwrap(), "Attn: Nurses".to_owned());

        let tag = TagV3::new(&["dummy", "tag"]);
        assert!(tag.parse_title().is_err());
    }

    #[test]
    fn test_kind_tag() {
        let tag = TagV3::new(&["k", "30023"]);
        assert_eq!(tag.parse_kind().unwrap(), EventKind::LongFormContent);

        let tag = TagV3::new(&["k"]);
        assert!(tag.parse_kind().is_err());

        let tag = TagV3::new_kind(EventKind::ZapRequest);
        assert_eq!(tag.parse_kind().unwrap(), EventKind::ZapRequest);
    }
}
