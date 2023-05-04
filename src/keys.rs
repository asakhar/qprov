use std::{
  io::{ErrorKind, Read, Write},
  path::Path,
};

use serde::{Deserialize, Serialize};

use crate::signatures;

use crc::{Crc, CRC_32_ISCSI};

pub const CASTAGNOLI: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

pub type PlainText = rmce::PlainSecret;
pub type EncPubKey = rmce::PublicKey;
pub type EncSecKey = rmce::SecretKey;
pub type Encapsulated = rmce::ShareableSecret;
pub type SigPubKey = crate::signatures::PublicKey;
pub type SigSecKey = crate::signatures::SecretKey;
pub type Signature = crate::signatures::Signature;

pub trait FileSerializeIdHelper {
  fn id() -> [u8; 4];
}

impl FileSerializeIdHelper for Certificate {
  fn id() -> [u8; 4] {
    [1, 0, 0, 0]
  }
}
impl FileSerializeIdHelper for CertificateChain {
  fn id() -> [u8; 4] {
    [2, 0, 0, 0]
  }
}
impl FileSerializeIdHelper for CertificateRequest {
  fn id() -> [u8; 4] {
    [3, 0, 0, 0]
  }
}
impl FileSerializeIdHelper for PubKeyPair {
  fn id() -> [u8; 4] {
    [4, 0, 0, 0]
  }
}
impl FileSerializeIdHelper for SecKeyPair {
  fn id() -> [u8; 4] {
    [5, 0, 0, 0]
  }
}

pub trait FileSerialize
where
  Self: 'static + Serialize + serde::de::DeserializeOwned + FileSerializeIdHelper,
{
  fn to_file(&self, file_path: impl AsRef<Path>) -> std::io::Result<()> {
    let mut file = std::fs::File::create(file_path)?;
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&Self::id());
    bincode::serialize_into(&mut buffer, &self)
      .map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err))?;
    let checksum = CASTAGNOLI.checksum(&buffer);
    file.write_all(&checksum.to_le_bytes())?;
    file.write_all(&buffer)?;
    Ok(())
  }

  fn from_file(file_path: impl AsRef<Path>) -> std::io::Result<Self>
  where
    Self: Sized,
  {
    let mut file = std::fs::File::open(file_path)?;
    let mut checksum = [0u8; 4];
    file.read_exact(&mut checksum)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let type_id = &buffer[0..4];
    if type_id != &Self::id() {
      return Err(std::io::Error::new(
        ErrorKind::InvalidData,
        "Invalid file type",
      ));
    }
    let checksum_actual = CASTAGNOLI.checksum(&buffer);
    if u32::from_le_bytes(checksum) != checksum_actual {
      return Err(std::io::Error::new(
        ErrorKind::InvalidData,
        "Corrupted file",
      ));
    }
    bincode::deserialize(&buffer[4..]).map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err))
  }
}

impl<T: 'static + Serialize + serde::de::DeserializeOwned + FileSerializeIdHelper> FileSerialize
  for T
{
}

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
  pub fn decapsulate(&self, encapsulated: &Encapsulated, len: usize) -> PlainText {
    encapsulated.open(len, &self.enc_key)
  }
  pub fn sign(&self, message: &[u8]) -> Signature {
    self.sig_key.sign(message)
  }
}
