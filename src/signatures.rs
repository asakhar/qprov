use serde::{Serialize, Deserialize};

use crate::openssl_rng;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(Box<[u8; Self::SIZE]>);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey(Box<[u8; Self::SIZE]>);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(Box<[u8; Self::SIZE]>);

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
  pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
    dilithium::sign::verify(message, signature.as_bytes(), self.as_bytes())
  }
}
impl Serialize for PublicKey {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
      where
          S: serde::Serializer {
      serializer.serialize_bytes(self.as_bytes())
  }
}
impl<'de> Deserialize<'de> for PublicKey {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
      where
          D: serde::Deserializer<'de> {
      deserializer.deserialize_byte_buf(rmce::BoxedArrayVisitor).map(Self)
  }
}
impl Signature {
  const SIZE: usize = dilithium::params::BYTES;
  pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
    &self.0
  }
}
impl Serialize for Signature {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_bytes(self.as_bytes())
  }
}
impl<'de> Deserialize<'de> for Signature {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    deserializer.deserialize_byte_buf(rmce::BoxedArrayVisitor).map(Self)
  }
}

impl SecretKey {
  const SIZE: usize = dilithium::params::SECRETKEYBYTES;
  pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
    &self.0
  }
  pub fn sign(&self, message: &[u8]) -> Signature {
    let mut sig_buf: Box<[u8; Signature::SIZE]> = vec![0u8; Signature::SIZE]
      .into_boxed_slice()
      .try_into()
      .unwrap();
    dilithium::sign::sign(&mut sig_buf, message, self.0.as_ref());
    Signature(sig_buf)
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
    deserializer.deserialize_byte_buf(rmce::BoxedArrayVisitor).map(Self)
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