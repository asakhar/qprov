use std::io::ErrorKind;

use serde::{Deserialize, Serialize};

use crate::signatures;

pub type PlainText = rmce::PlainSecret;
pub type EncPubKey = rmce::PublicKey;
pub type EncSecKey = rmce::SecretKey;
pub type Encapsulated = rmce::ShareableSecret;
pub type SigPubKey = crate::signatures::PublicKey;
pub type SigSecKey = crate::signatures::SecretKey;
pub type Signature = crate::signatures::Signature;

#[derive(Serialize, Deserialize)]
pub struct PubKeyPair {
  pub enc_key: EncPubKey,
  pub sig_key: SigPubKey,
}

#[derive(Serialize, Deserialize)]
pub struct SecKeyPair {
  pub enc_key: EncSecKey,
  pub sig_key: SigSecKey,
}

pub fn generate_key_pairs() -> (PubKeyPair, SecKeyPair) {
  let (enc_pub, enc_sec) = rmce::generate_keypair();
  let (sig_pub, sig_sec) = signatures::generate_keypair();
  (
    PubKeyPair {
      enc_key: enc_pub,
      sig_key: sig_pub,
    },
    SecKeyPair {
      enc_key: enc_sec,
      sig_key: sig_sec,
    },
  )
}

#[derive(Serialize, Deserialize)]
pub struct Certificate {
  pub pub_keys: PubKeyPair,
  pub contract: String,
  pub signature: Signature,
}

impl Certificate {
  pub fn from_file<P: AsRef<std::path::Path>>(p: P) -> std::io::Result<Self> {
    let file = std::fs::File::open(p.as_ref())?;
    bincode::deserialize_from(file).map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))
  }
  pub fn to_file<P: AsRef<std::path::Path>>(&self, p: P) -> std::io::Result<()> {
    let file = std::fs::File::create(p.as_ref())?;
    bincode::serialize_into(file, self).map_err(|e| std::io::Error::new(ErrorKind::Other, e))
  }
  pub fn verify(&self, pk: &SigPubKey) -> bool {
    let mut payload = Vec::new();
    bincode::serialize_into(&mut payload, &self.pub_keys).unwrap();
    bincode::serialize_into(&mut payload, &self.contract).unwrap();
    pk.verify(&payload, &self.signature)
  }
  pub fn create(pub_keys: PubKeyPair, contract: impl Into<String>, issuer_priv: SigSecKey) -> Self {
    let contract = contract.into();
    let mut payload = Vec::new();
    bincode::serialize_into(&mut payload, &pub_keys).unwrap();
    bincode::serialize_into(&mut payload, &contract).unwrap();
    let signature = issuer_priv.sign(payload.as_slice());
    Self {
      pub_keys,
      contract,
      signature,
    }
  }
}

impl PubKeyPair {
  pub fn encapsulate(&self, len: usize) -> (Encapsulated, PlainText) {
    self.enc_key.session(len)
  }
  pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
    self.sig_key.verify(message, signature)
  }
}

impl SecKeyPair {
  pub fn decapsulate(&self, encapsulated: &Encapsulated, len: usize) -> PlainText {
    encapsulated.open(len, &self.enc_key)
  }
  pub fn sign(&self, message: &[u8]) -> Signature {
    self.sig_key.sign(message)
  }
}
