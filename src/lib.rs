mod keys;
mod openssl_rng;
mod pqschannel;
pub mod serialization;
pub mod sized_read_writes;

pub use keys::generate_key_pairs;
pub use keys::Certificate;
pub use keys::Encapsulated;
pub use keys::PlainText;
pub use keys::PubKeyPair;
pub use keys::SecKeyPair;
pub use pqschannel::PqsChannel;

pub enum PqsContext {
  Client {
    ca_cert: Certificate,
    cert: Option<Certificate>,
    secret: Option<SecKeyPair>,
  },
  Server {
    ca_cert: Option<Certificate>,
    cert: Certificate,
    secret: SecKeyPair,
  },
}

impl PqsContext {
  pub fn server(cert: Certificate, secret: SecKeyPair) -> Self {
    Self::Server {
      ca_cert: None,
      cert,
      secret,
    }
  }
  pub fn client(ca_cert: Certificate) -> Self {
    Self::Client {
      ca_cert,
      cert: None,
      secret: None,
    }
  }
}
