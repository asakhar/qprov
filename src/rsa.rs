use std::marker::PhantomData;

use openssl::{
  hash::MessageDigest,
  pkey::{PKey, Private, Public},
  rsa::Rsa,
};
use serde::{de::Visitor, Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct RsaPublic(PKey<Public>);

#[derive(Debug, Clone)]
pub struct RsaPrivate(PKey<Private>);

impl RsaPublic {
  pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
    let Ok(mut verifier) = openssl::sign::Verifier::new(MessageDigest::sha512(), &self.0) else {return false;};
    verifier.verify_oneshot(signature, message).unwrap_or(false)
  }
  pub fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
    let encrypter = openssl::encrypt::Encrypter::new(&self.0).ok()?;
    let mut result = vec![0u8; encrypter.encrypt_len(message).ok()?];
    let len = encrypter.encrypt(message, &mut result).ok()?;
    result.truncate(len);
    Some(result)
  }
}

impl RsaPrivate {
  pub fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
    let mut signer = openssl::sign::Signer::new(MessageDigest::sha512(), &self.0).ok()?;
    signer.sign_oneshot_to_vec(message).ok()
  }
  pub fn decrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
    let decrypter = openssl::encrypt::Decrypter::new(&self.0).ok()?;
    let mut result = vec![0u8; decrypter.decrypt_len(message).ok()?];
    let len = decrypter.decrypt(message, &mut result).ok()?;
    result.truncate(len);
    Some(result)
  }
}

impl Serialize for RsaPublic {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_bytes(&self.0.public_key_to_der().unwrap())
  }
}

impl<'de> Deserialize<'de> for RsaPublic {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    Ok(Self(
      deserializer.deserialize_byte_buf(RsaKeyVisitor::<Public>::default())?,
    ))
  }
}

impl Serialize for RsaPrivate {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_bytes(&self.0.private_key_to_der().unwrap())
  }
}

impl<'de> Deserialize<'de> for RsaPrivate {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    Ok(Self(
      deserializer.deserialize_byte_buf(RsaKeyVisitor::<Private>::default())?,
    ))
  }
}

struct RsaKeyVisitor<T> {
  _p: PhantomData<T>,
}

impl<T> Default for RsaKeyVisitor<T> {
  fn default() -> Self {
    Self {
      _p: Default::default(),
    }
  }
}

impl<'de> Visitor<'de> for RsaKeyVisitor<Public> {
  type Value = PKey<Public>;

  fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
    formatter.write_str("rsa public key in der SubjectPublicKeyInfo format")
  }
  fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
  where
    E: serde::de::Error,
  {
    PKey::public_key_from_der(v).map_err(E::custom)
  }
}

impl<'de> Visitor<'de> for RsaKeyVisitor<Private> {
  type Value = PKey<Private>;

  fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
    formatter.write_str("rsa private key in der PrivateKeyInfo format")
  }
  fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
  where
    E: serde::de::Error,
  {
    PKey::private_key_from_der(v).map_err(E::custom)
  }
}

pub fn generate_keypair() -> Option<(RsaPublic, RsaPrivate)> {
  let rsa_private = openssl::rsa::Rsa::generate(4096).ok()?;
  let rsa_public = Rsa::from_public_components(
    rsa_private.n().to_owned().ok()?,
    rsa_private.e().to_owned().ok()?,
  )
  .unwrap();
  Some((
    RsaPublic(PKey::from_rsa(rsa_public).ok()?),
    RsaPrivate(PKey::from_rsa(rsa_private).ok()?),
  ))
}
