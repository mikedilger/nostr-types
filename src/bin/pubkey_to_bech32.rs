// TEMPORARILY
#![allow(clippy::uninlined_format_args)]

use nostr_types::PublicKey;

fn main() {
    let hex = rpassword::prompt_password("Public key hex: ").unwrap();
    let public_key = PublicKey::try_from_hex_string(&hex).unwrap();
    let bech32 = public_key.try_as_bech32_string().unwrap();
    println!("{}", bech32);
}
