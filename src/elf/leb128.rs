/// uLEB128

/// エラー情報
#[derive(Debug)]
pub enum LEB128Error {
    DecodeError
}

trait ULEB128 {
    /// LEBデータRead
    fn decode<R: std::io::Read>(reader: &mut R) -> Result<u64, LEB128Error> {
        // 終了判定であるMSB=0まで、続ける
        let mut val: u64 = 0;
        let mut s = 0;
        loop {
            let mut b = [0; 1];
            if reader.read_exact(&mut b).is_err() {
                return Err(LEB128Error::DecodeError);
            }

            // LEBデータを取得・復元
            let b_val = u8::from_le_bytes(b) as u64;
            val |= (b_val & 0x7F) << s * 7;

            // MSG=0であれば、終了
            if 0 == b_val & 0x80 {
                break;
            }

            // 次回のシフト量を更新
            s += 1;
        }
        Ok(val)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    struct Test {}
    impl ULEB128 for Test {}

    #[test]
    fn test() {
        let mut b: &[u8] = &[0];
        assert_eq!(0, Test::decode(&mut b).unwrap());

        b = &[1];
        assert_eq!(1, Test::decode(&mut b).unwrap());

        b = &[0xE5, 0x8E, 0x26];
        assert_eq!(624485, Test::decode(&mut b).unwrap());

        b = &[0x7F];
        assert_eq!(127, Test::decode(&mut b).unwrap());

        b = &[0xEA, 0x93, 0x21];
        assert_eq!(543210, Test::decode(&mut b).unwrap());
    }
}
