use std::path::PathBuf;

use crate::types::{TestType, Wg};

pub struct PathGenerator {
    base_dir: PathBuf,
    base_file_name: String,
}

impl PathGenerator {
    pub fn new(wg: Wg, test_type: TestType, packet_count: usize) -> Self {
        let mut base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // CARGO_MANIFEST_DIR points to NepTUN/xtask. Popping takes us back to the root of NepTUN
        base_dir.pop();

        let base_file_name = format!("xray_{wg}_{test_type}_{packet_count}",);

        Self {
            base_dir,
            base_file_name,
        }
    }

    pub fn analyze_script(&self) -> PathBuf {
        self.base_dir.join("xray/analyze.py")
    }

    pub fn results_dir(&self) -> PathBuf {
        self.base_dir.join("xray/results")
    }

    pub fn binary_dir(&self) -> PathBuf {
        self.base_dir.join("target/release")
    }

    pub fn base(&self) -> PathBuf {
        self.results_dir().join(&self.base_file_name)
    }

    pub fn pcap(&self) -> PathBuf {
        self.results_dir()
            .join(format!("{}.pcap", self.base_file_name))
    }

    pub fn csv(&self) -> PathBuf {
        self.results_dir()
            .join(format!("{}.csv", self.base_file_name))
    }

    pub fn png(&self) -> PathBuf {
        self.results_dir()
            .join(format!("{}.png", self.base_file_name))
    }

    pub fn txt(&self) -> PathBuf {
        self.results_dir()
            .join(format!("{}.txt", self.base_file_name))
    }
}
