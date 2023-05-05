use serde::{de::Visitor, Deserialize, Serialize, ser::SerializeTupleStruct};

use crate::openssl_rng;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(Box<[u8; Self::SIZE]>);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey(Box<[u8; Self::SIZE]>);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(Box<[u8; Self::SIZE]>, Vec<u8>);

pub fn generate_keypair() -> (PublicKey, SecretKey) {
  let mut pub_buf = boxed_array::from_default();

  let mut sec_buf = boxed_array::from_default();
  dilithium::sign::keypair(
    &mut openssl_rng::OpenSslRng::new(),
    &mut pub_buf,
    &mut sec_buf,
  );
  (PublicKey(pub_buf), SecretKey(sec_buf))
}

impl PublicKey {
  const SIZE: usize = dilithium::params::PUBLICKEYBYTES;
  pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
    &self.0
  }
  pub fn verify(&self, message: &[u8], signature: &[u8; Signature::SIZE]) -> bool {
    dilithium::sign::verify(message, signature, self.as_bytes())
  }
}
impl Serialize for PublicKey {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_bytes(self.as_bytes())
  }
}
impl<'de> Deserialize<'de> for PublicKey {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    deserializer
      .deserialize_byte_buf(rmce::BoxedArrayVisitor)
      .map(Self)
  }
}
impl Signature {
  const SIZE: usize = dilithium::params::BYTES;
  pub fn pq_as_bytes(&self) -> &[u8; Self::SIZE] {
    &self.0
  }
  pub fn rsa_as_bytes(&self) -> &[u8] {
    &self.1
  }
  pub fn from_both(pq_sig: Box<[u8; Self::SIZE]>, rsa_sig: Vec<u8>) -> Self {
    Self(pq_sig, rsa_sig)
  }
}
impl Serialize for Signature {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let mut seq = serializer.serialize_tuple_struct("Signature", 2)?;
    seq.serialize_field(self.0.as_slice())?;
    seq.serialize_field(&self.1)?;
    seq.end()
  }
}

struct SignatureVisitor;
impl<'de> Visitor<'de> for SignatureVisitor {
  type Value = Signature;
  fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
    formatter.write_str("two signatures: dilithium and rsa")
  }
  fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
  where
    E: serde::de::Error,
  {
    let mut pq: Box<[u8; Signature::SIZE]> = boxed_array::from_default();
    if v.len() <= Signature::SIZE {
      return Err(E::invalid_length(v.len(), &self));
    }
    pq.copy_from_slice(&v[..Signature::SIZE]);
    let rsa = v[Signature::SIZE..].to_vec();
    Ok(Signature(pq, rsa))
  }
  fn visit_byte_buf<E>(self, mut v: Vec<u8>) -> Result<Self::Value, E>
  where
    E: serde::de::Error,
  {
    if v.len() <= Signature::SIZE {
      return Err(E::invalid_length(v.len(), &self));
    }
    let rsa = v[Signature::SIZE..].to_vec();
    v.truncate(Signature::SIZE);
    let pq = v.into_boxed_slice().try_into().unwrap();
    Ok(Signature(pq, rsa))
  }
}

impl<'de> Deserialize<'de> for Signature {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    deserializer.deserialize_tuple_struct("Signature", 2, SignatureVisitor)
  }
}

impl SecretKey {
  const SIZE: usize = dilithium::params::SECRETKEYBYTES;
  pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
    &self.0
  }
  pub fn sign(&self, message: &[u8]) -> Box<[u8; Signature::SIZE]> {
    let mut sig_buf: Box<[u8; Signature::SIZE]> = boxed_array::from_default();
    dilithium::sign::sign(&mut sig_buf, message, self.0.as_ref());
    sig_buf
  }
}

impl Serialize for SecretKey {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_bytes(self.as_bytes())
  }
}

impl<'de> Deserialize<'de> for SecretKey {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    deserializer
      .deserialize_byte_buf(rmce::BoxedArrayVisitor)
      .map(Self)
  }
}

impl TryFrom<&[u8]> for PublicKey {
  type Error = rmce::Error;
  fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
    let len = value.len();
    if value.len() != Self::SIZE {
      return Err(Self::Error::InvalidLength {
        got: len,
        expected: Self::SIZE,
      });
    }
    let mut buf: Box<[u8; Self::SIZE]> = boxed_array::from_default();
    buf.copy_from_slice(value);
    Ok(Self(buf))
  }
}

impl TryFrom<Vec<u8>> for PublicKey {
  type Error = rmce::Error;
  fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
    let len = value.len();
    Ok(PublicKey(value.into_boxed_slice().try_into().map_err(
      |_| Self::Error::InvalidLength {
        got: len,
        expected: Self::SIZE,
      },
    )?))
  }
}
