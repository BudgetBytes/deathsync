use rand;
use rsa::{
    pkcs1::{
        DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey,
        LineEnding,
    },
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use anyhow::Result;

pub fn new(bits: usize) -> Result<(RsaPublicKey, RsaPrivateKey)> {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, bits)?;
    let pub_key = RsaPublicKey::from(&priv_key);
    Ok((pub_key, priv_key))
}


pub fn pub_encode(key: RsaPublicKey) -> Result<String>{
    let enc_key = EncodeRsaPublicKey::to_pkcs1_pem(&key, LineEnding::LF)?;
    Ok(enc_key)
}

pub fn priv_encode(key: RsaPrivateKey) -> Result<String> {
    let enc_key = EncodeRsaPrivateKey::to_pkcs1_pem(&key, LineEnding::LF)?.to_string();
    Ok(enc_key)
}

pub fn pub_decode(pem: String) -> Result<RsaPublicKey> {
    let key = DecodeRsaPublicKey::from_pkcs1_pem(&pem)?;
    Ok(key)
}

pub fn priv_decode(pem: String) -> Result<RsaPrivateKey> {
    let key: RsaPrivateKey = DecodeRsaPrivateKey::from_pkcs1_pem(&pem)?;
    Ok(key)
}

pub fn encrypt(data: &[u8], pub_key: RsaPublicKey) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let enc_data = pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, &data[..])?;
    Ok(enc_data)
}

pub fn decrypt(data: &[u8], priv_key: RsaPrivateKey) -> Result<Vec<u8>> {
    let dec_data = priv_key
        .decrypt(Pkcs1v15Encrypt, &data)?;
    Ok(dec_data)
}


