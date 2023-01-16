use nostr_types::RelayInformationDocument;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use std::env;
use std::time::Duration;

fn main() {
    let mut args = env::args();
    let _ = args.next(); // program name
    let url = match args.next() {
        Some(u) => u,
        None => panic!("Usage: fetch_nip11 <RelayURL>")
    };

    let uri: http::Uri = url.parse::<http::Uri>().unwrap();
    let authority = uri.authority().unwrap().as_str();
    let host = authority
        .find('@')
        .map(|idx| authority.split_at(idx + 1).1)
        .unwrap_or_else(|| authority);
    if host.is_empty() {
        panic!("Empty hostname");
    }

    let client = Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Some(Duration::from_secs(60)))
        .timeout(Some(Duration::from_secs(60)))
        .connection_verbose(true)
        .build().unwrap();
    let response = client.get(format!("https://{}", host))
        .header("Host", host)
        .header("Accept", "application/nostr+json")
        .send().unwrap();
    let rid = response.json::<RelayInformationDocument>().unwrap();
    println!("{}", rid);
}
