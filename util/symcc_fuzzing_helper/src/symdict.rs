use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::cmp::Ordering;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Eq, PartialEq, Debug)]
pub struct DictWord {
    pub begin: u32,
    pub end: u32,
    pub data: Vec<u8>,
}

impl Ord for DictWord {
    fn cmp(&self, other: &Self) -> Ordering {
        self.end
            .cmp(&other.end)
            .then_with(|| self.begin.cmp(&other.begin))
    }
}

impl PartialOrd for DictWord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl DictWord {
    pub fn decode(reader: &mut Bytes) -> Result<Option<DictWord>> {
        if !reader.has_remaining() {
            return Ok(None);
        }; // EOF
        let begin = reader.get_u32_le();
        let end = reader.get_u32_le();

        // println!("begin: {}, end: {}", begin, end);
        assert!(begin <= end);
        let data = reader
            .copy_to_bytes((end as usize).abs_diff(begin as usize) + 1)
            .to_vec();

        Ok(Some(DictWord { begin, end, data }))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];

        buf.put_u32_le(self.begin);
        buf.put_u32_le(self.end);
        buf.put_u8(self.data.len() as u8);
        buf.put_slice(&self.data);

        Ok(buf)
    }
}

pub struct SymDict(pub Vec<DictWord>);

impl SymDict {
    pub fn read_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let mut file = File::open(path.as_ref()).expect("failed to open symdict file");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let mut reader = bytes::Bytes::from(buf);

        let mut vec = vec![];

        while let Some(dictword) = DictWord::decode(&mut reader)? {
            println!(
                "begin: {}, end: {}, data: {:?}",
                dictword.begin, dictword.end, dictword.data
            );
            vec.push(dictword);
        }

        Ok(SymDict(vec))
    }

    pub fn write_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let mut file = File::create(path.as_ref())?;

        let mut buf = BytesMut::new();
        buf.put_u32_le(self.0.len() as u32);
        file.write_all(&buf)?;

        for word in self.0.iter() {
            if word.end - word.begin >= 255 {
                continue;
            }

            let buf = word.encode()?;
            file.write_all(&buf)?;
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
        let mut dict =
            SymDict::read_from_file(symdict_file).expect("Failed to read raw symdict file");
        dict.sort();
        dict.write_to_file(target_file)?;

        Ok(())
    }
}

#[test]
fn test_symdict_dedup() {
    let file1 = "/home/thematch/Desktop/mysymcc/mytest/dict/id:000005,src:000004,time:631,execs:7810,op:havoc,rep:8,+cov"
        .to_string();
    let file2 = "/home/thematch/Desktop/mysymcc/mytest/dict/id:000005,trimmed".to_string();
    let _ = SymDict::trim_symdict(file1, file2);
}
