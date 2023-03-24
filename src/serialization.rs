use crate::sized_read_writes::{ReadSizedExt, WriteSizedExt};

pub trait Serializable {
  fn serialize<Drain: std::io::Write>(&self, drain: &mut Drain) -> std::io::Result<()>;
}

impl Serializable for String {
  fn serialize<Drain: std::io::Write>(&self, drain: &mut Drain) -> std::io::Result<()> {
    drain.write_sized(self)?;
    Ok(())
  }
}

impl Serializable for Vec<u8> {
  fn serialize<Drain: std::io::Write>(&self, drain: &mut Drain) -> std::io::Result<()> {
    drain.write_sized(self)?;
    Ok(())
  }
}

impl<T: Serializable> Serializable for Vec<T> {
  fn serialize<Drain: std::io::Write>(&self, drain: &mut Drain) -> std::io::Result<()> {
    drain.write_all(&self.len().to_be_bytes())?;
    for item in self.iter() {
      item.serialize(drain)?;
    }
    Ok(())
  }
}

pub trait Deserializable {
  fn deserialize<Source: std::io::Read>(source: &mut Source) -> std::io::Result<Self>
  where
    Self: Sized;
}

impl Deserializable for String {
  fn deserialize<Source: std::io::Read>(source: &mut Source) -> std::io::Result<Self> {
    String::from_utf8(source.read_sized()?)
      .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
  }
}

impl Deserializable for Vec<u8> {
  fn deserialize<Source: std::io::Read>(source: &mut Source) -> std::io::Result<Self>
  where
    Self: Sized,
  {
    source.read_sized()
  }
}

impl<T: Deserializable> Deserializable for Vec<T> {
  fn deserialize<Source: std::io::Read>(source: &mut Source) -> std::io::Result<Self> {
    let mut len_buf = [0u8; std::mem::size_of::<usize>()];
    source.read_exact(&mut len_buf)?;
    let len = usize::from_be_bytes(len_buf);
    let mut res = Vec::with_capacity(len);
    for _ in 0..len {
      res.push(T::deserialize(source)?);
    }
    Ok(res)
  }
}
