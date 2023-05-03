use std::{io::ErrorKind, path::Path};

use serde::{Deserialize, Serialize};

use crate::signatures;

pub type PlainText = rmce::PlainSecret;
pub type EncPubKey = rmce::PublicKey;
pub type EncSecKey = rmce::SecretKey;
pub type Encapsulated = rmce::ShareableSecret;
pub type SigPubKey = crate::signatures::PublicKey;
pub type SigSecKey = crate::signatures::SecretKey;
pub type Signature = crate::signatures::Signature;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PubKeyPair {
  pub enc_key: EncPubKey,
  pub sig_key: SigPubKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateRequest {
  pub pub_keys: PubKeyPair,
  pub owner: String,
  pub contract: String,
}

impl CertificateRequest {
  pub fn new(pub_keys: PubKeyPair, owner: impl Into<String>, contract: impl Into<String>) -> Self {
    Self {
      pub_keys,
      owner: owner.into(),
      contract: contract.into(),
    }
  }
  pub fn sign(self, issuer: impl Into<String>, issuer_priv: SigSecKey) -> Certificate {
    let contents = CertificateContents::from_request(self, issuer);
    let payload = bincode::serialize(&contents).unwrap();
    let signature = issuer_priv.sign(payload.as_slice());
    Certificate {
      contents,
      signature,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateContents {
  pub issuer: String,
  pub pub_keys: PubKeyPair,
  pub owner: String,
  pub contract: String,
}

impl CertificateContents {
  pub fn from_request(req: CertificateRequest, issuer: impl Into<String>) -> Self {
    Self {
      issuer: issuer.into(),
      pub_keys: req.pub_keys,
      owner: req.owner,
      contract: req.contract,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
  pub contents: CertificateContents,
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
    let payload = bincode::serialize(&self.contents).unwrap();
    pk.verify(&payload, &self.signature)
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateChain {
  pub chain: Vec<Certificate>,
}

impl CertificateChain {
  pub fn root(root: Certificate) -> Option<Self> {
    if !root.verify(&root.contents.pub_keys.sig_key) {
      return None;
    }
    Some(Self { chain: vec![root] })
  }
  pub fn append(&mut self, child: Certificate) -> bool {
    if !child.verify(&self.chain.last().unwrap().contents.pub_keys.sig_key) {
      return false;
    }
    self.chain.push(child);
    true
  }
  pub fn verify(
    &self,
    ca_cert: &Certificate,
    verificator: impl Fn(&Certificate, &Certificate) -> bool,
  ) -> bool {
    let Some(first) = self.chain.iter().next() else {
      return false;
    };
    if !first.verify(&ca_cert.contents.pub_keys.sig_key) {
      return false;
    }
    for pair in self.chain.windows(2).rev() {
      let (issuer, target) = (&pair[0], &pair[1]);
      if !target.verify(&issuer.contents.pub_keys.sig_key) {
        return false;
      }
      if !verificator(issuer, target) {
        return false;
      }
    }
    true
  }
  pub fn from_file(file_path: impl AsRef<Path>) -> std::io::Result<Self> {
    let file = std::fs::File::open(file_path)?;
    bincode::deserialize_from(file).map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err))
  }
  pub fn get_target(&self) -> &Certificate {
    self.chain.last().unwrap()
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
  pub fn from_file(file_path: impl AsRef<Path>) -> std::io::Result<Self> {
    let file = std::fs::File::open(file_path)?;
    bincode::deserialize_from(file).map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err))
  }
  pub fn decapsulate(&self, encapsulated: &Encapsulated, len: usize) -> PlainText {
    encapsulated.open(len, &self.enc_key)
  }
  pub fn sign(&self, message: &[u8]) -> Signature {
    self.sig_key.sign(message)
  }
}
