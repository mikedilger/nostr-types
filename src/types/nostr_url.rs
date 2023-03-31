use super::{EventPointer, Id, Profile, PublicKey};
use lazy_static::lazy_static;

/// A bech32 sequence representing a nostr object (or set of objects)
// note, internally we store them as the object the sequence represents
#[derive(Debug)]
pub enum NostrBech32 {
    /// npub - a NostrBech32 representing a public key
    Pubkey(PublicKey),
    /// nprofile - a NostrBech32 representing a public key and a set of relay URLs
    Profile(Profile),
    /// note - a NostrBech32 representing an event
    Id(Id),
    /// nevent - a NostrBech32 representing an event and a set of relay URLs
    EventPointer(EventPointer),
}

impl std::fmt::Display for NostrBech32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            NostrBech32::Pubkey(pk) => write!(f, "{}", pk.as_bech32_string()),
            NostrBech32::Profile(p) => write!(f, "{}", p.as_bech32_string()),
            NostrBech32::Id(i) => write!(f, "{}", i.as_bech32_string()),
            NostrBech32::EventPointer(ep) => write!(f, "{}", ep.as_bech32_string()),
        }
    }
}

impl NostrBech32 {
    /// Create from a `PublicKey`
    pub fn new_pubkey(pubkey: PublicKey) -> NostrBech32 {
        NostrBech32::Pubkey(pubkey)
    }

    /// Create from a `Profile`
    pub fn new_profile(profile: Profile) -> NostrBech32 {
        NostrBech32::Profile(profile)
    }

    /// Create from an `Id`
    pub fn new_id(id: Id) -> NostrBech32 {
        NostrBech32::Id(id)
    }

    /// Create from an `EventPointer`
    pub fn new_event_pointer(ep: EventPointer) -> NostrBech32 {
        NostrBech32::EventPointer(ep)
    }

    /// Try to convert a string into a NostrBech32. Must not have leading or trailing
    /// junk for this to work.
    pub fn try_from_string(s: &str) -> Option<NostrBech32> {
        if s.get(..5) == Some("npub1") {
            if let Ok(pk) = PublicKey::try_from_bech32_string(s) {
                return Some(NostrBech32::Pubkey(pk));
            }
        } else if s.get(..9) == Some("nprofile1") {
            if let Ok(p) = Profile::try_from_bech32_string(s) {
                return Some(NostrBech32::Profile(p));
            }
        } else if s.get(..5) == Some("note1") {
            if let Ok(id) = Id::try_from_bech32_string(s) {
                return Some(NostrBech32::Id(id));
            }
        } else if s.get(..7) == Some("nevent1") {
            if let Ok(ep) = EventPointer::try_from_bech32_string(s) {
                return Some(NostrBech32::EventPointer(ep));
            }
        }
        None
    }

    /// Find all `NostrBech32`s in a string, returned in the order found
    pub fn find_all_in_string(s: &str) -> Vec<NostrBech32> {
        let mut output: Vec<NostrBech32> = Vec::new();
        let mut cursor = 0;
        while let Some((relstart, relend)) = find_nostr_bech32_pos(&s[cursor..]) {
            if let Some(nurl) = NostrBech32::try_from_string(&s[cursor + relstart..cursor + relend])
            {
                output.push(nurl);
            }
            cursor += relend;
        }
        output
    }
}

/// A Nostr URL (starting with 'nostr:')
#[derive(Debug)]
pub struct NostrUrl(pub NostrBech32);

impl std::fmt::Display for NostrUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "nostr:")?;
        self.0.fmt(f)
    }
}

impl NostrUrl {
    /// Create a new NostrUrl from a NostrBech32
    pub fn new(bech32: NostrBech32) -> NostrUrl {
        NostrUrl(bech32)
    }

    /// Try to convert a string into a NostrUrl. Must not have leading or trailing
    /// junk for this to work.
    pub fn try_from_string(s: &str) -> Option<NostrUrl> {
        if s.get(..6) != Some("nostr:") {
            return None;
        }
        NostrBech32::try_from_string(&s[6..]).map(NostrUrl)
    }

    /// Find all `NostrUrl`s in a string, returned in the order found
    /// (If not prefixed with 'nostr:' they will not count, see NostrBech32)
    pub fn find_all_in_string(s: &str) -> Vec<NostrUrl> {
        let mut output: Vec<NostrUrl> = Vec::new();
        let mut cursor = 0;
        while let Some((relstart, relend)) = find_nostr_url_pos(&s[cursor..]) {
            if let Some(nurl) = NostrUrl::try_from_string(&s[cursor + relstart..cursor + relend]) {
                output.push(nurl);
            }
            cursor += relend;
        }
        output
    }

    /// This converts all recognized bech32 sequences into proper nostr URLs by adding
    /// the "nostr:" prefix where missing.
    pub fn urlize(s: &str) -> String {
        let mut output: String = String::with_capacity(s.len());
        let mut cursor = 0;
        while let Some((relstart, relend)) = find_nostr_bech32_pos(&s[cursor..]) {
            // If it already has it, leave it alone
            if relstart >= 6 && s.get(cursor + relstart - 6..cursor + relstart) == Some("nostr:") {
                output.push_str(&s[cursor..cursor + relend]);
            } else {
                output.push_str(&s[cursor..cursor + relstart]);
                output.push_str("nostr:");
                output.push_str(&s[cursor + relstart..cursor + relend]);
            }
            cursor += relend;
        }
        output.push_str(&s[cursor..]);
        output
    }
}

/// Returns start and end position of next valid NostrBech32
pub fn find_nostr_bech32_pos(s: &str) -> Option<(usize, usize)> {
    // BECH32 Alphabet:
    // qpzry9x8gf2tvdw0s3jn54khce6mua7l
    // acdefghjklmnpqrstuvwxyz023456789
    use regex::Regex;
    lazy_static! {
        static ref BECH32_RE: Regex = Regex::new(
            r#"(?:^|[^a-zA-Z0-9])((?:note|nevent|nprofile|npub)1[ac-hj-np-z02-9]{58,})(?:$|[^a-zA-Z0-9])"#
        ).expect("Could not compile nostr URL regex");
    }
    BECH32_RE.captures(s).map(|cap| {
        let mat = cap.get(1).unwrap();
        (mat.start(), mat.end())
    })
}

/// Returns start and end position of next valid NostrUrl
pub fn find_nostr_url_pos(s: &str) -> Option<(usize, usize)> {
    // BECH32 Alphabet:
    // qpzry9x8gf2tvdw0s3jn54khce6mua7l
    // acdefghjklmnpqrstuvwxyz023456789
    use regex::Regex;
    lazy_static! {
        static ref NOSTRURL_RE: Regex = Regex::new(
            r#"(?:^|[^a-zA-Z0-9])(nostr:(?:note|nevent|nprofile|npub)1[ac-hj-np-z02-9]{58,})(?:$|[^a-zA-Z0-9])"#
        ).expect("Could not compile nostr URL regex");
    }
    NOSTRURL_RE.captures(s).map(|cap| {
        let mat = cap.get(1).unwrap();
        (mat.start(), mat.end())
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_nostr_bech32_try_from_string() {
        let a = "npub1sn0wdenkukak0d9dfczzeacvhkrgz92ak56egt7vdgzn8pv2wfqqhrjdv9";
        let nurl = NostrBech32::try_from_string(a).unwrap();
        assert!(matches!(nurl, NostrBech32::Pubkey(..)));

        let b = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
        let nurl = NostrBech32::try_from_string(b).unwrap();
        assert!(matches!(nurl, NostrBech32::Profile(..)));

        let c = "note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc";
        let nurl = NostrBech32::try_from_string(c).unwrap();
        assert!(matches!(nurl, NostrBech32::Id(..)));

        let d = "nevent1qqstna2yrezu5wghjvswqqculvvwxsrcvu7uc0f78gan4xqhvz49d9spr3mhxue69uhkummnw3ez6un9d3shjtn4de6x2argwghx6egpr4mhxue69uhkummnw3ez6ur4vgh8wetvd3hhyer9wghxuet5nxnepm";
        let nurl = NostrBech32::try_from_string(d).unwrap();
        assert!(matches!(nurl, NostrBech32::EventPointer(..)));

        // too short
        let short = "npub1sn0wdenkukak0d9dfczzeacvhkrgz92ak56egt7vdgzn8pv2wfqqhrjdv";
        assert!(NostrBech32::try_from_string(short).is_none());

        // bad char
        let badchar = "note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6bqc";
        assert!(NostrBech32::try_from_string(badchar).is_none());

        // unknown prefix char
        let unknown = "nurl1sn0wdenkukak0d9dfczzeacvhkrgz92ak56egt7vdgzn8pv2wfqqhrjdv9";
        assert!(NostrBech32::try_from_string(unknown).is_none());
    }

    #[test]
    fn test_nostr_urlize() {
        let sample = r#"This is now the offical Gossip Client account.  Please follow it.  I will be reposting it's messages for some time until it catches on.

nprofile1qqsrjerj9rhamu30sjnuudk3zxeh3njl852mssqng7z4up9jfj8yupqpzamhxue69uhhyetvv9ujumn0wd68ytnfdenx7tcpz4mhxue69uhkummnw3ezummcw3ezuer9wchszxmhwden5te0dehhxarj9ekkj6m9v35kcem9wghxxmmd9uq3xamnwvaz7tm0venxx6rpd9hzuur4vghsz8nhwden5te0dehhxarj94c82c3wwajkcmr0wfjx2u3wdejhgtcsfx2xk

#[1]
"#;
        let fixed = NostrUrl::urlize(sample);
        println!("{fixed}");
        assert!(fixed.contains("nostr:nprofile1"));

        let sample2 = r#"Have you been switching nostr clients lately?
Could be related to:
nostr:note10ttnuuvcs29y3k23gwrcurw2ksvgd7c2rrqlfx7urmt5m963vhss8nja90
"#;
        let nochange = NostrUrl::urlize(sample2);
        assert_eq!(sample2.len(), nochange.len());

        let sample3 = r#"Have you been switching nostr clients lately?
Could be related to:
note10ttnuuvcs29y3k23gwrcurw2ksvgd7c2rrqlfx7urmt5m963vhss8nja90
"#;
        let fixed = NostrUrl::urlize(sample3);
        assert!(fixed.contains("nostr:note1"));
        assert!(fixed.len() > sample3.len());
    }

     #[test]
    fn test_nostr_url_unicode_issues() {
        let sample = r#"🌝🐸note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc"#;
        assert!(NostrUrl::try_from_string(sample).is_none())
    }
}
