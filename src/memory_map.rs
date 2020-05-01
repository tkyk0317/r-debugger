use std::fs;
use std::io::{BufRead, BufReader};
use std::collections::HashMap;
use nix::unistd::{ Pid };

// メモリマップデータ
#[derive(Debug, Clone)]
pub struct MapInfo {
    pub start_address: String,
    pub end_address: String,
    pub permission: String,
}

// メモリーマップ
pub struct MemoryMap {
    maps_path: String,
    maps: HashMap<String, Vec<MapInfo>>
}

/// メモリマップ実装
impl MemoryMap {
    /// コンストラクタ
    pub fn new(pid: Pid) -> Self {
        MemoryMap {
            maps_path: format!("/proc/{}/maps", pid),
            maps: HashMap::new()
        }
    }

    /// メモリマップロード
    ///
    /// 対象プログラムのスタートアドレス
    pub fn load(&mut self) -> &HashMap<String, Vec<MapInfo>> {
        let content = BufReader::new(
            fs::File::open(&self.maps_path).unwrap_or_else(|p| panic!("cannot open file: {}", p))
        );

        // mapsファイルを走査し、各ファイルごとのメモリマップを登録
        for l in content.lines() {
            let line = l.unwrap();
            let s_line = line.split_whitespace()
                             .collect::<Vec<&str>>();

            // ファイル名をキーとして、HashMapへ登録
            let key =
                if s_line.len() >= 6 {
                    s_line[5].to_string()
                }
                else {
                    "none".to_string()
                };

            // 開始アドレスやパーミッションを取り出す
            let map_info = self.maps.get_mut(&key);
            let addr_range = s_line[0].split('-').collect::<Vec<&str>>();
            let new_map_info = MapInfo {
                start_address: addr_range[0].to_string(),
                end_address: addr_range[1].to_string(),
                permission: s_line[1].to_string()
            };

            // 既に登録されている場合はMapInfoを追加
            match map_info {
                Some(m) => {
                    let mut maps = m.clone();
                    maps.push(new_map_info);
                    self.maps.insert(key, maps);
                }
                _ => {
                    self.maps.insert(key, vec![new_map_info]);
                }
            };
        }

        &self.maps
    }
}
