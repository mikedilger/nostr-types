use nostr_types::PrivateKey;
use zeroize::Zeroize;

// Turn a hex private key into an encrypted private key
fn main() {
    let hex_private_key = rpassword::prompt_password("Hex Private Key: ").unwrap();
    let mut password = rpassword::prompt_password("Password: ").unwrap();
    let private_key =
        PrivateKey::try_from_hex_string(&hex_private_key).expect("Could not import private key");
    let encrypted_private_key = private_key
        .export_encrypted(&password)
        .expect("Could not export encrypted private key");
    println!("Encrypted private key: {}", encrypted_private_key);
    password.zeroize();
}
