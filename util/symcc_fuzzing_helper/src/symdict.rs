use anyhow::Result;
use bytes::{Buf, BufMut};
use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Eq, PartialEq, Debug)]
pub struct DictWord {
    pub begin: u32,
    pub end: u32,
    pub data: Vec<u8>,
}

impl Ord for DictWord {
    fn cmp(&self, other: &Self) -> Ordering {
        self.begin
            .cmp(&other.begin)
            .then_with(|| self.end.cmp(&other.end))
    }
}

impl PartialOrd for DictWord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

const U32_SIZE: usize = std::mem::size_of::<u32>();

impl DictWord {
    pub fn decode(raw_data: &[u8]) -> Result<DictWord> {
        let begin = (&raw_data[0..U32_SIZE]).get_u32();
        let end = (&raw_data[U32_SIZE..2 * U32_SIZE]).get_u32();
        let data =
            raw_data[2 * U32_SIZE..2 * U32_SIZE - (end as usize - begin as usize) + 1].to_vec();
        Ok(DictWord { begin, end, data })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];

        buf.put_u32(self.begin);
        buf.put_u32(self.end);
        buf.put_slice(&self.data);

        Ok(buf)
    }
}

pub struct SymDict(pub Vec<DictWord>);

impl SymDict {
    pub fn read_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path.as_ref())?;
        let reader = BufReader::new(file);
        let mut vec = vec![];

        for line in reader.lines() {
            let line = line?;
            let dictword = DictWord::decode(line.as_bytes())?;
            vec.push(dictword);
        }
        Ok(SymDict(vec))
    }

    pub fn write_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let mut file = File::create(path.as_ref())?;

        for word in self.0.iter() {
            let buf = word.encode()?;
            file.write_all(&buf)?;
            file.write_all(b"\n")?;
        }
        file.flush()?;
        Ok(())
    }

    pub fn sort(&mut self) {
        self.0.sort();
        self.0.dedup_by(|a, b| a.begin == b.begin && a.end == b.end);
    }

    pub fn trim_symdict(
        symdict_file: impl AsRef<Path>,
        target_file: impl AsRef<Path>,
    ) -> Result<()> {
        let mut dict = SymDict::read_from_file(symdict_file)?;
        dict.sort();
        dict.write_to_file(target_file)?;

        Ok(())
    }
}
