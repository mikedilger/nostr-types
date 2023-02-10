// TEMPORARILY
#![allow(clippy::uninlined_format_args)]

use nostr_types::{PrivateKey, PublicKey};

fn main() {
    println!("bech32: ");
    let mut bech32 = String::new();
    let stdin = std::io::stdin();
    stdin.read_line(&mut bech32).unwrap();
    let bech32 = bech32.trim();
    //let bech32 = rpassword::prompt_password("bech32: ").unwrap();

    if let Ok(key) = PublicKey::try_from_bech32_string(bech32) {
        println!("Public Key: {}", key.as_hex_string());
    } else if let Ok(mut key) = PrivateKey::try_from_bech32_string(bech32) {
        println!("Private Key: {}", key.as_hex_string());
    } else {
        println!("Invalid.");
    }
}
