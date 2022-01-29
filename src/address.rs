/// Address Object
pub trait AddressTrait {
    fn get(&self) -> usize;
}

/// 相対アドレス（オフセットで表現されているものに使用）
#[derive(Clone)]
pub struct AdrFromRel {
    base: usize, // ベースアドレス
    addr: usize, // アドレス
}

impl AdrFromRel {
    /// コンストラクタ
    pub fn new(b_addr: usize, address: usize) -> Self {
        AdrFromRel {
            base: b_addr,
            addr: address,
        }
    }
}

impl AddressTrait for AdrFromRel {
    /// アドレス取得
    fn get(&self) -> usize {
        self.base + self.addr
    }
}

/// 絶対アドレス
#[derive(Clone)]
pub struct AdrFromAbs {
    addr: usize, // アドレス
}

impl AdrFromAbs {
    /// コンストラクタ
    pub fn new(address: usize) -> Self {
        AdrFromAbs { addr: address }
    }
}

impl AddressTrait for AdrFromAbs {
    /// アドレス取得
    fn get(&self) -> usize {
        self.addr
    }
}
