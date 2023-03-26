use crate::{
  openssl_rng,
  serialization::{Deserializable, Serializable},
};

pub type PlainText = rmce::PlainSecret;
pub struct SigPubKey(Box<[u8; Self::SIZE]>);
pub struct SigSecKey(Box<[u8; Self::SIZE]>);
pub struct Signature(Box<[u8; Self::SIZE]>);
pub type EncPubKey = rmce::PublicKey;
pub type EncSecKey = rmce::SecretKey;
pub type Encapsulated = rmce::ShareableSecret;

pub struct PubKeyPair {
  enc_key: EncPubKey,
  sig_key: SigPubKey,
}

pub struct SecKeyPair {
  enc_key: EncSecKey,
  sig_key: SigSecKey,
}

pub fn generate_key_pairs() -> (PubKeyPair, SecKeyPair) {
  let (enc_pub, enc_sec) = rmce::generate_keypair();
  let mut sig_pub_buf: Box<[u8; SigPubKey::SIZE]> = vec![0u8; SigPubKey::SIZE]
    .into_boxed_slice()
    .try_into()
    .unwrap();
  let mut sig_sec_buf: Box<[u8; SigSecKey::SIZE]> = vec![0u8; SigSecKey::SIZE]
    .into_boxed_slice()
    .try_into()
    .unwrap();
  dilithium::sign::keypair(
    &mut openssl_rng::OpenSslRng::new(),
    &mut sig_pub_buf,
    &mut sig_sec_buf,
  );
  (
    PubKeyPair {
      enc_key: enc_pub,
      sig_key: SigPubKey(sig_pub_buf),
    },
    SecKeyPair {
      enc_key: enc_sec,
      sig_key: SigSecKey(sig_sec_buf),
    },
  )
}

pub struct Certificate {
  pub pub_keys: PubKeyPair,
  pub issuer: String,
  pub owner: String,
  pub alt_names: Vec<String>,
  pub signature: Signature,
}

impl Serializable for Certificate {
  fn serialize<Drain: std::io::Write>(&self, drain: &mut Drain) -> std::io::Result<()> {
    self.pub_keys.serialize(drain)?;
    self.issuer.serialize(drain)?;
    self.owner.serialize(drain)?;
    self.alt_names.serialize(drain)?;
    self.signature.serialize(drain)?;
    Ok(())
  }
}

impl Deserializable for Certificate {
  fn deserialize<Source: std::io::Read>(source: &mut Source) -> std::io::Result<Self>
  where
    Self: Sized,
  {
    let pub_keys = PubKeyPair::deserialize(source)?;
    let issuer = String::deserialize(source)?;
    let owner = String::deserialize(source)?;
    let alt_names = Vec::deserialize(source)?;
    let signature = Signature::deserialize(source)?;
    Ok(Self {
      pub_keys,
      issuer,
      owner,
      alt_names,
      signature,
    })
  }
}

impl Certificate {
  pub fn from_file<P: AsRef<std::path::Path>>(p: P) -> std::io::Result<Self> {
    let mut file = std::fs::File::open(p.as_ref())?;
    Self::deserialize(&mut file)
  }
  pub fn to_file<P: AsRef<std::path::Path>>(&self, p: P) -> std::io::Result<()> {
    let mut file = std::fs::File::create(p.as_ref())?;
    self.serialize(&mut file)
  }
  pub fn verify(&self, pk: &PubKeyPair) -> bool {
    let mut payload = Vec::new();
    self.pub_keys.serialize(&mut payload).unwrap();
    self.issuer.serialize(&mut payload).unwrap();
    self.owner.serialize(&mut payload).unwrap();
    self.alt_names.serialize(&mut payload).unwrap();
    pk.verify(&payload, &self.signature)
  }
  pub fn create(
    pub_keys: PubKeyPair,
    issuer: String,
    owner: String,
    alt_names: Vec<String>,
    issuer_priv: SecKeyPair,
  ) -> Self {
    let mut payload = Vec::new();
    pub_keys.serialize(&mut payload).unwrap();
    issuer.serialize(&mut payload).unwrap();
    owner.serialize(&mut payload).unwrap();
    alt_names.serialize(&mut payload).unwrap();
    let signature = issuer_priv.sign(payload.as_slice());
    Self {
      pub_keys,
      issuer,
      owner,
      alt_names,
      signature,
    }
  }
}

impl SigPubKey {
  const SIZE: usize = dilithium::params::PUBLICKEYBYTES;
  pub fn as_bytes(&self) -> &[u8] {
    self.0.as_ref()
  }
  pub fn as_array_ref(&self) -> &[u8; Self::SIZE] {
    &self.0
  }
  pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
    dilithium::sign::verify(message, signature.as_array_ref(), self.as_array_ref())
  }
}
impl Signature {
  const SIZE: usize = dilithium::params::BYTES;
  pub fn as_bytes(&self) -> &[u8] {
    self.0.as_ref()
  }
  pub fn as_array_ref(&self) -> &[u8; Self::SIZE] {
    &self.0
  }
}

impl Deserializable for Signature {
  fn deserialize<Source: std::io::Read>(source: &mut Source) -> std::io::Result<Self>
  where
    Self: Sized,
  {
    let mut sig_buf = vec![0u8; dilithium::params::BYTES];
    source.read_exact(&mut sig_buf)?;
    Ok(Signature(sig_buf.into_boxed_slice().try_into().unwrap()))
  }
}
impl Serializable for Signature {
  fn serialize<Drain: std::io::Write>(&self, drain: &mut Drain) -> std::io::Result<()> {
    drain.write_all(self.0.as_ref())?;
    Ok(())
  }
}
impl SigSecKey {
  const SIZE: usize = dilithium::params::SECRETKEYBYTES;
  pub fn sign(&self, message: &[u8]) -> Signature {
    let mut sig_buf: Box<[u8; Signature::SIZE]> = vec![0u8; Signature::SIZE]
      .into_boxed_slice()
      .try_into()
      .unwrap();
    dilithium::sign::sign(&mut sig_buf, message, self.0.as_ref());
    Signature(sig_buf)
  }
}

impl TryFrom<Vec<u8>> for SigPubKey {
  type Error = rmce::Error;
  fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
    let len = value.len();
    Ok(SigPubKey(value.into_boxed_slice().try_into().map_err(
      |_| Self::Error::InvalidLength {
        got: len,
        expected: Self::SIZE,
      },
    )?))
  }
}

impl Serializable for PubKeyPair {
  fn serialize<Drain: std::io::Write>(&self, drain: &mut Drain) -> std::io::Result<()> {
    drain.write_all(self.enc_key.as_bytes())?;
    drain.write_all(self.sig_key.as_bytes())?;
    Ok(())
  }
}

impl Deserializable for PubKeyPair {
  fn deserialize<Source: std::io::Read>(source: &mut Source) -> std::io::Result<Self>
  where
    Self: Sized,
  {
    let mut enc_buf = vec![0u8; EncPubKey::SIZE];
    source.read_exact(&mut enc_buf)?;
    let mut sig_buf = vec![0u8; SigPubKey::SIZE];
    source.read_exact(&mut sig_buf)?;
    let enc_key = EncPubKey::try_from(enc_buf).unwrap();
    let sig_key = SigPubKey(sig_buf.into_boxed_slice().try_into().unwrap());
    Ok(PubKeyPair { enc_key, sig_key })
  }
}

impl PubKeyPair {
  pub fn encapsulate(&self) -> (Encapsulated, PlainText) {
    self
      .enc_key
      .session(openssl::cipher::Cipher::aes_128_cbc().key_length())
  }
  pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
    self.sig_key.verify(message, signature)
  }
}

impl Serializable for EncSecKey {
  fn serialize<Drain: std::io::Write>(&self, drain: &mut Drain) -> std::io::Result<()> {
    drain.write_all(self.as_bytes())
  }
}
impl Serializable for SigSecKey {
  fn serialize<Drain: std::io::Write>(&self, drain: &mut Drain) -> std::io::Result<()> {
    drain.write_all(self.0.as_slice())
  }
}

impl Serializable for SecKeyPair {
  fn serialize<Drain: std::io::Write>(&self, drain: &mut Drain) -> std::io::Result<()> {
    self.enc_key.serialize(drain)?;
    self.sig_key.serialize(drain)?;
    Ok(())
  }
}

impl Deserializable for EncSecKey {
  fn deserialize<Source: std::io::Read>(source: &mut Source) -> std::io::Result<Self>
  where
    Self: Sized,
  {
    let mut buf = vec![0u8; Self::SIZE];
    source.read_exact(&mut buf)?;
    Ok(Self::try_from(buf).unwrap())
  }
}

impl Deserializable for SigSecKey {
  fn deserialize<Source: std::io::Read>(source: &mut Source) -> std::io::Result<Self>
  where
    Self: Sized,
  {
    let mut buf = vec![0u8; Self::SIZE];
    source.read_exact(&mut buf)?;
    Ok(Self(buf.into_boxed_slice().try_into().unwrap()))
  }
}

impl Deserializable for SecKeyPair {
  fn deserialize<Source: std::io::Read>(source: &mut Source) -> std::io::Result<Self>
  where
    Self: Sized,
  {
    let enc_key = EncSecKey::deserialize(source)?;
    let sig_key = SigSecKey::deserialize(source)?;
    Ok(SecKeyPair { enc_key, sig_key })
  }
}

impl SecKeyPair {
  pub fn decapsulate(&self, encapsulated: &Encapsulated) -> PlainText {
    encapsulated.open(
      openssl::cipher::Cipher::aes_128_cbc().key_length(),
      &self.enc_key,
    )
  }
  pub fn sign(&self, message: &[u8]) -> Signature {
    self.sig_key.sign(message)
  }
}

impl Serializable for Encapsulated {
  fn serialize<Drain: std::io::Write>(&self, drain: &mut Drain) -> std::io::Result<()> {
    drain.write_all(self.as_bytes())
  }
}

impl Deserializable for Encapsulated {
  fn deserialize<Source: std::io::Read>(source: &mut Source) -> std::io::Result<Self>
  where
    Self: Sized,
  {
    let mut buf = [0u8; Encapsulated::SIZE];
    source.read_exact(&mut buf)?;
    Ok(buf.into())
  }
}
