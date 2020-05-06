/// uLEB128

/// エラー情報
#[derive(Debug)]
pub enum LEB128Error {
    DecodeError
}

pub trait ULEB128 {
    /// LEBデータRead
    ///
    /// 読み取ったサイズとvalueをタプルで返す
    fn decode<R: std::io::Read>(reader: &mut R) -> Result<(u64, u64), LEB128Error> {
        // 終了判定であるMSB=0まで、続ける
        let mut val: u64 = 0;
        let mut size = 0;
        let mut s = 0;
        loop {
            let mut b = [0; 1];
            if reader.read_exact(&mut b).is_err() {
                return Err(LEB128Error::DecodeError);
            }

            // LEBデータを取得・復元
            let b_val = u8::from_le_bytes(b) as u64;
            val |= (b_val & 0x7F) << s;
            size += 1;

            // MSG=0であれば、終了
            if 0 == b_val & 0x80 {
                break;
            }

            // 次回のシフト量を更新
            s += 7;
        }
        Ok((size, val))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    struct Test {}
    impl ULEB128 for Test {}

    #[test]
    fn test() {
        {
            let mut b: &[u8] = &[0];
            let ret = Test::decode(&mut b).unwrap();
            assert_eq!(1, ret.0);
            assert_eq!(0, ret.1);
        }
        {
            let mut b: &[u8] = &[1];
            let ret = Test::decode(&mut b).unwrap();
            assert_eq!(1, ret.0);
            assert_eq!(1, ret.1);
        }
        {
            let mut b: &[u8] = &[0xE5, 0x8E, 0x26];
            let ret = Test::decode(&mut b).unwrap();
            assert_eq!(3, ret.0);
            assert_eq!(624485, ret.1);
        }
        {
            let mut b: &[u8] = &[0x7F];
            let ret = Test::decode(&mut b).unwrap();
            assert_eq!(1, ret.0);
            assert_eq!(127, ret.1);
        }
        {
            let mut b: &[u8] = &[0xEA, 0x93, 0x21];
            let ret = Test::decode(&mut b).unwrap();
            assert_eq!(3, ret.0);
            assert_eq!(543210, ret.1);
        }
    }
}
