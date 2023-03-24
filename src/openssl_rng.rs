pub struct OpenSslRng;

impl OpenSslRng {
  pub fn new() -> Self {
    Self
  }
}

impl rand::Rng for OpenSslRng {
  fn next_u32(&mut self) -> u32 {
    let mut buf = [0u8; std::mem::size_of::<u32>()];
    openssl::rand::rand_bytes(&mut buf).unwrap();
    u32::from_le_bytes(buf)
  }

  fn next_u64(&mut self) -> u64 {
    let mut buf = [0u8; std::mem::size_of::<u64>()];
    openssl::rand::rand_bytes(&mut buf).unwrap();
    u64::from_le_bytes(buf)
  }

  fn fill_bytes(&mut self, dest: &mut [u8]) {
    openssl::rand::rand_bytes(dest).unwrap();
  }
}
