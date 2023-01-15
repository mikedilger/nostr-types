use nostr_types::{EncryptedPrivateKey, PrivateKey};

fn main() {
    println!("DANGER this exposes the private key.");
    println!("encrypted private key: ");
    let mut epk = String::new();
    let stdin = std::io::stdin();
    stdin.read_line(&mut epk).unwrap();
    let epk = EncryptedPrivateKey(epk.trim().to_owned());

    let password = rpassword::prompt_password("Password: ").unwrap();
    let mut private_key = PrivateKey::import_encrypted(&epk, &password)
        .expect("Could not import encrypted private key");
    println!("Private key: {}", private_key.as_hex_string());
}
