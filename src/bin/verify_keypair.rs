// Copyright 2015-2020 nostr-proto Developers
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// This file may not be copied, modified, or distributed except according to those terms.

use k256::schnorr::{SigningKey, VerifyingKey};
use std::env;
use std::process;

fn main() {
    let mut args = env::args();

    if args.len() != 3 {
        println!("Usage:  verify_keypair <public> <private>");
        process::exit(1);
    }

    args.next().unwrap(); // the program name

    let verifying_key_string = args.next().unwrap();
    let verifying_key_bytes: Vec<u8> = match hex::decode(verifying_key_string) {
        Ok(v) => v,
        Err(e) => {
            println!("FAILURE: public key is not valid hex: {:?}", e);
            process::exit(1);
        }
    };
    let verifying_key = match VerifyingKey::from_bytes(&verifying_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            println!("FAILURE: public key is not valid: {:?}", e);
            process::exit(1);
        }
    };

    let signing_key_string = args.next().unwrap();
    let signing_key_bytes: Vec<u8> = match hex::decode(signing_key_string) {
        Ok(v) => v,
        Err(e) => {
            println!("FAILURE: private key is not valid hex: {:?}", e);
            process::exit(1);
        }
    };
    let signing_key = match SigningKey::from_bytes(&signing_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            println!("FAILURE: private key is not valid: {:?}", e);
            process::exit(1);
        }
    };

    let matching_key = signing_key.verifying_key();

    if verifying_key != *matching_key {
        println!("FAILURE: Keys are NOT a valid pair");
        process::exit(1);
    } else {
        println!("SUCCESS: Keys match.");
    }
}
