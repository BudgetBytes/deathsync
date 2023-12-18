use anyhow::{anyhow, Result};
use crypt;
use hex::{decode, encode};
use reqwest::blocking::Client;
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::prelude::*;
use x25519_dalek::{EphemeralSecret, PublicKey};

const PAYLOAD_PATH: &str = "./test/outtest";

fn main() -> Result<()> {
    let secret = EphemeralSecret::random();
    let public = PublicKey::from(&secret);
    let pub_hex = encode(public);

    let client = Client::new();
    let post_res = match client
        .post("http://localhost:8080/exchange")
        .body(pub_hex)
        .send()
    {
        Ok(resp) => resp.text()?,
        Err(err) => panic!("Error: {}", err),
    };

    let json_value: Value = serde_json::from_str(&post_res).unwrap();
    let publickey = json_value["publickey"].as_str().unwrap();
    let chunks = json_value["chunks"].as_u64().unwrap() as usize;

    let peer_public: Result<[u8; 32], _> = decode(publickey).unwrap().as_slice().try_into();
    let peer_public_key = match peer_public {
        Ok(array) => PublicKey::from(array),
        Err(_) => {
            return Err(anyhow!("Invalid public key"));
        }
    };

    let shared_secret = secret.diffie_hellman(&peer_public_key);

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(PAYLOAD_PATH)?;

    for id in 0..chunks {
        if id % 100 == 0 {
            println!("Doing chunk #{id}");
        }
        let get_resp = match client
            .get(format!("http://localhost:8080/death_sync/{id}"))
            .send()
        {
            Ok(resp) => resp.text()?,
            Err(err) => panic!("Error: {}", err),
        };

        let json_value: Value = serde_json::from_str(&get_resp).unwrap();
        let enc_payload = json_value["enc_payload"].as_str().unwrap();
        let enc_nonce = json_value["nonce"].as_str().unwrap();
        let dec_payload = decode(enc_payload).unwrap();
        let dec_nonce = decode(enc_nonce).unwrap();

        let key = crypt::str_to_key(shared_secret.as_bytes());
        let nonce = crypt::str_to_nonce(&dec_nonce);
        let plaintext = crypt::decrypt(nonce, key, &dec_payload).unwrap();

        file.write_all(&plaintext)?;
    }

    let end_resp = match client.get("http://localhost:8080/end").send() {
        Ok(resp) => resp.text()?,
        Err(err) => panic!("Error: {}", err),
    };

    println!("{end_resp}");

    Ok(())
}
