/// Address Object
#[derive(Clone)]
pub struct Address {
    base: usize, // ベースアドレス
    addr: usize, // アドレス
}

impl Address {
    /// コンストラクタ
    pub fn new(b_addr: usize, address: usize) -> Self {
        Address { base: b_addr, addr: address }
    }

    /// アドレス取得
    pub fn get(&self) -> usize { self.base + self.addr }
}
