use nostr_types::PrivateKey;
use zeroize::Zeroize;

// The zeroize in here is really silly because we print it.
fn main() {
    let mut hex = rpassword::prompt_password("Private key hex: ").unwrap();
    let mut private_key = PrivateKey::try_from_hex_string(&hex).unwrap();
    hex.zeroize();
    let mut bech32 = private_key.try_as_bech32_string().unwrap();
    println!("{}", bech32);
    bech32.zeroize();
}
