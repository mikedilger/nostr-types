// Copyright 2015-2020 nostr-proto Developers
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// This file may not be copied, modified, or distributed except according to those terms.

use k256::schnorr::SigningKey;
use rand_core::OsRng;

fn main() {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    println!("PUBLIC: {:x}", verifying_key.to_bytes());
    println!("PRIVATE: {:x}", signing_key.to_bytes());
}
