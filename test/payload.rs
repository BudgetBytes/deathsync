use actix_web::{
    get, post,
    web::{Bytes, Data, Path},
    App, HttpRequest, HttpServer, Responder,
};
use crypt;
use std::fs;
use std::sync::{Arc, Mutex};
use std::{collections::HashMap, net::IpAddr};
use hex::{encode, decode};

const PAYLOAD_PATH: &str = "./test/payload.rs";

#[derive(Clone)]
struct ClientsState {
    hashmap: Arc<Mutex<HashMap<IpAddr, String>>>,
    chunked_payload: Vec<Vec<u8>>,
}

#[post("/init")]
async fn init(req: HttpRequest, body: Bytes, data: Data<ClientsState>) -> impl Responder {
    let mut key_table = data.hashmap.lock().unwrap();

    if let Some(val) = req.peer_addr() {
        let ip = val.ip();
        if !key_table.contains_key(&ip) {
            let client_pubkey = String::from_utf8(decode(body.to_vec()).unwrap()).unwrap();
            key_table.insert(ip, client_pubkey);
            return format!("{}", data.chunked_payload.len());
        } else {
            eprintln!("Collision detected for IP: {}", ip);
            return format!("{}", -1);
        }
    };
    return format!("{}", 0);
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
                let pub_key = crypt::pub_decode(value.clone()).expect("failed to decode ");
                let enc_chunk = crypt::encrypt(&chunk, pub_key).expect("failed to encrypt");
                let hex_chunk = encode(enc_chunk);
                return hex_chunk;
            }
            None => {
                eprintln!("The ip {} didn't initialized before syncing", ip);
            }
        }
    };

    return String::from("Error");
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let content = fs::read(PAYLOAD_PATH)?;
    let chunk_size = 128; 
    let chunked_payload: Vec<Vec<u8>> = content.chunks(chunk_size).map(|chunk| chunk.to_vec()).collect();
    let client_data = ClientsState {
        hashmap: Arc::new(Mutex::new(HashMap::new())),
        chunked_payload
    };
    
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(client_data.clone()))
            .service(init)
            .service(death_sync)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
