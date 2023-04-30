use std::{
  collections::VecDeque,
  io::{ErrorKind, Read, Write},
};

use crate::{
  serialization::{AsyncDeserialize, AsyncSerialize},
  PqsClientContext, PqsServerContext,
};

use super::{
  serialization::{Deserialize, Serialize},
  Certificate, Encapsulated, PlainText,
};
use openssl::{aes::AesKey, symm::Mode};

const BLOCK_SIZE: usize = 0x10;
const IV_SIZE: usize = 0x20;
const KEY_SIZE: usize = 0x20;

pub struct  PqsChannel<Stream> {
  stream: Stream,
  inbuffer: Vec<u8>,
}

// pub struct Encrypter {
//   key: AesKey,
//   iv: [u8; IV_SIZE],
// }

// impl Encrypter {
//   pub fn new(key: &[u8], iv: [u8; IV_SIZE]) -> Self {
//     let key = AesKey::new_encrypt(key).unwrap();
//     Self { key, iv }
//   }
//   pub fn update(&mut self, input: &[u8], output: &mut VecDeque<u8>) {
//     let input_len_mod16 = input.len() % BLOCK_SIZE;
//     let padding_len = (BLOCK_SIZE - input_len_mod16) as u8;
//     let mut padded_input = input.to_vec();
//     let range = 0..padding_len;
//     let mapped = range.map(|_| padding_len);
//     padded_input.extend(mapped);
//     let len = padded_input.len();
//     output.write_all(&(len as u128).to_be_bytes()).unwrap();
//     let mapped = (0..len).map(|_| 0);
//     output.extend(mapped);
//     let output = output.make_contiguous();
//     let start = output.len() - len;
//     openssl::aes::aes_ige(
//       &padded_input,
//       &mut output[start..],
//       &self.key,
//       &mut self.iv,
//       Mode::Encrypt,
//     );
//   }
// }

// pub struct Decrypter {
//   key: AesKey,
//   iv: [u8; IV_SIZE],
//   buffer: VecDeque<u8>,
// }
// impl Decrypter {
//   pub fn new(key: &[u8], iv: [u8; IV_SIZE]) -> Self {
//     let key = AesKey::new_decrypt(key).unwrap();
//     Self {
//       key,
//       iv,
//       buffer: Default::default(),
//     }
//   }
//   pub fn update(&mut self, input: &[u8], output: &mut VecDeque<u8>) {
//     self.buffer.write(input).unwrap();
//     while self.buffer.len() > BLOCK_SIZE {
//       let mut len_buf = [0u8; BLOCK_SIZE];
//       let buffer = self.buffer.make_contiguous();
//       len_buf.copy_from_slice(&buffer[..BLOCK_SIZE]);
//       let len = u128::from_be_bytes(len_buf) as usize;
//       if buffer.len() < BLOCK_SIZE + len {
//         break;
//       }
//       let input = &buffer[BLOCK_SIZE..len + BLOCK_SIZE];
//       output.write_all(input).unwrap();
//       let out = output.make_contiguous();
//       let start = out.len() - len;
//       openssl::aes::aes_ige(
//         input,
//         &mut out[start..],
//         &self.key,
//         &mut self.iv,
//         Mode::Decrypt,
//       );
//       drop(self.buffer.drain(0..len + BLOCK_SIZE));
//       let padding = *out.last().unwrap() as usize;
//       drop(output.drain(output.len() - padding..));
//     }
//   }
// }


// pub struct PqsChannel<Stream> {
//   stream: Stream,
//   decrypter: Decrypter,
//   encrypter: Encrypter,
//   deinbuffer: Vec<u8>,
//   decrypted_buffer: VecDeque<u8>,
//   encrypted_buffer: VecDeque<u8>,
// }

// impl<Stream: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Send + Unpin> PqsChannel<Stream> {
//   async fn new_inner_async(mut stream: Stream, plain_secret: PlainText) -> std::io::Result<Self> {
//     let mut write_iv = [0u8; IV_SIZE];
//     let mut read_iv = [0u8; IV_SIZE];
//     openssl::rand::rand_bytes(&mut write_iv).unwrap();
//     stream.write_all(&write_iv).await?;
//     stream.read_exact(&mut read_iv).await?;
//     let encrypter = Encrypter::new(plain_secret.as_bytes(), write_iv);
//     let decrypter = Decrypter::new(plain_secret.as_bytes(), read_iv);
//     let deinbuffer = vec![0u8; BLOCK_SIZE * 5];

//     Ok(Self {
//       stream,
//       encrypter,
//       decrypter,
//       deinbuffer,
//       decrypted_buffer: Default::default(),
//       encrypted_buffer: Default::default(),
//     })
//   }
//   pub async fn async_client(
//     mut stream: Stream,
//     context: &PqsClientContext,
//   ) -> std::io::Result<Self> {
//     let cert = Certificate::adeserialize(&mut stream).await?;
//     if !cert.verify(&context.ca_cert.pub_keys) {
//       return Err(std::io::Error::new(
//         ErrorKind::NotConnected,
//         "Certificate validation failed for server",
//       ));
//     }
//     let (shared_secret, plain_secret) = cert.pub_keys.encapsulate(KEY_SIZE);
//     shared_secret.aserialize(&mut stream).await?;
//     Self::new_inner_async(stream, plain_secret).await
//   }
//   pub async fn async_server(
//     mut stream: Stream,
//     context: &PqsServerContext,
//   ) -> std::io::Result<Self> {
//     context.cert.aserialize(&mut stream).await?;
//     let shared_secret = Encapsulated::adeserialize(&mut stream).await?;
//     let plain_secret = context.secret.decapsulate(&shared_secret, KEY_SIZE);
//     Self::new_inner_async(stream, plain_secret).await
//   }
// }

// impl<Stream: Read + Write> PqsChannel<Stream> {
//   fn new_inner(mut stream: Stream, plain_secret: PlainText) -> std::io::Result<Self> {
//     let mut write_iv = [0u8; IV_SIZE];
//     let mut read_iv = [0u8; IV_SIZE];
//     openssl::rand::rand_bytes(&mut write_iv).unwrap();
//     stream.write_all(&write_iv)?;
//     stream.read_exact(&mut read_iv)?;
//     let encrypter = Encrypter::new(plain_secret.as_bytes(), write_iv);
//     let decrypter = Decrypter::new(plain_secret.as_bytes(), read_iv);
//     let deinbuffer = vec![0u8; BLOCK_SIZE * 5];

//     Ok(Self {
//       stream,
//       encrypter,
//       decrypter,
//       deinbuffer,
//       decrypted_buffer: Default::default(),
//       encrypted_buffer: Default::default(),
//     })
//   }
//   pub fn client(mut stream: Stream, context: &PqsClientContext) -> std::io::Result<Self> {
//     let cert = Certificate::deserialize(&mut stream)?;
//     if !cert.verify(&context.ca_cert.pub_keys) {
//       return Err(std::io::Error::new(
//         ErrorKind::NotConnected,
//         "Certificate validation failed for server",
//       ));
//     }
//     let (shared_secret, plain_secret) = cert.pub_keys.encapsulate(KEY_SIZE);
//     shared_secret.serialize(&mut stream)?;
//     Self::new_inner(stream, plain_secret)
//   }
//   pub fn server(mut stream: Stream, context: &PqsServerContext) -> std::io::Result<Self> {
//     context.cert.serialize(&mut stream)?;
//     let shared_secret = Encapsulated::deserialize(&mut stream)?;
//     let plain_secret = secret.decapsulate(&shared_secret, KEY_SIZE);
//     Self::new_inner(stream, plain_secret)
//   }
// }
// impl PqsChannel<std::net::TcpStream> {
//   pub fn set_read_timeout(&mut self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
//     self.stream.set_read_timeout(timeout)
//   }
// }

// impl<Stream: tokio::io::AsyncRead> tokio::io::AsyncReadExt for PqsChannel<Stream> {}

// impl<Stream: Read> Read for PqsChannel<Stream> {
//   fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
//     if self.decrypted_buffer.len() > 0 {
//       let read = self.decrypted_buffer.read(buf)?;
//       return Ok(read);
//     }
//     if buf.len() > self.deinbuffer.len() + 0x20 {
//       let diff = buf.len() - self.deinbuffer.len();
//       let range = 0..diff;
//       let mapped = range.map(|_| 0);
//       self.deinbuffer.extend(mapped);
//     }
//     let mut read = 0;
//     while read == 0 {
//       let len = self.stream.read(&mut self.deinbuffer)?;
//       if len == 0 {
//         break;
//       }
//       self
//         .decrypter
//         .update(&self.deinbuffer[..len], &mut self.decrypted_buffer);
//       read = self.decrypted_buffer.read(buf)?;
//     }
//     Ok(read)
//   }
// }

// impl<Stream: Write> Write for PqsChannel<Stream> {
//   fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
//     self.encrypter.update(buf, &mut self.encrypted_buffer);
//     let ready_to_write = self.encrypted_buffer.make_contiguous();
//     let written = self.stream.write(ready_to_write)?;
//     drop(self.encrypted_buffer.drain(0..written));
//     Ok(buf.len())
//   }
//   fn flush(&mut self) -> std::io::Result<()> {
//     let ready_to_write = self.encrypted_buffer.make_contiguous();
//     self.stream.write_all(ready_to_write)?;
//     self.stream.flush()
//   }
// }
