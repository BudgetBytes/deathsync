use anyhow::Result;
use crypt;
use hex::{decode, encode};
use reqwest::blocking::Client;
use std::fs::OpenOptions;
use std::io::prelude::*;

const PAYLOAD_PATH: &str = "./test/out.rs";

fn main() -> Result<()> {
    let (pub_key, priv_key) = crypt::new(2048)?;
    let pub_enc = crypt::pub_encode(pub_key.clone())?;
    let pub_hex = encode(pub_enc);

    let client = Client::new();
    let post_res = match client
        .post("http://localhost:8080/init")
        .body(pub_hex)
        .send()
    {
        Ok(resp) => resp.text()?,
        Err(err) => panic!("Error: {}", err),
    };
    let chunks: usize = post_res.parse().unwrap();

    // Open the file in append mode
    // Open the file in append mode, create it if it does not exist
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(PAYLOAD_PATH)?;

    // Loop from 0 to chunks - 1
    for id in 0..chunks {
        let get_resp = match client
            .get(format!("http://localhost:8080/death_sync/{}", id))
            .send()
        {
            Ok(resp) => resp.text()?,
            Err(err) => panic!("Error: {}", err),
        };
        let enc_body = decode(get_resp)?;

        let dec_body = crypt::decrypt(&enc_body, priv_key.clone())?;

        // Append the decrypted body to the file
        file.write_all(&dec_body)?;
    }

    let end_resp = match client.get("http://localhost:8080/end").send() {
        Ok(resp) => resp.text()?,
        Err(err) => panic!("Error: {}", err),
    };

    println!("{end_resp}");

    Ok(())
}
