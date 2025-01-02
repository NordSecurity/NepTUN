use std::{path::PathBuf, thread::JoinHandle};

use clap::{builder::TypedValueParser as _, Parser};
use xray::{
    path_generator::PathGenerator,
    types::{TestType, Wg},
    CRYPTO_PORT, PLAINTEXT_PORT, WG_NAME, WG_PORT,
};
use xshell::{cmd, Shell};

macro_rules! run_cmd {
    ($sh:expr, $cmd:literal) => {{
        cmd!($sh, $cmd).run().map_err(|e| Error::XShell {
            cmd: $cmd,
            inner: e,
        })
    }};
}

type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error executing command: {cmd}")]
    XShell {
        cmd: &'static str,
        #[source]
        inner: xshell::Error,
    },
}

#[derive(Parser, Debug)]
pub struct Cmd {
    /// Which wireguard adapter to use
    /// - NepTUN will be built and used from the same repo
    /// - wggo must be installed and locatable as 'wireguard-go'
    ///
    #[arg(
        long,
        verbatim_doc_comment,
        default_value_t = Wg::NepTUN,
        value_parser = clap::builder::PossibleValuesParser::new(["neptun", "native", "wggo"])
            .map(|s| s.parse::<Wg>().unwrap()),
    )]
    wg: Wg,

    /// What kind of test to run.
    /// - a crypto test sends from crypto socket to plaintext socket
    /// - a plaintext test sends from plaintext socket to crypto socket
    /// - a bidir test sends packets in both directions
    ///
    #[arg(
        long,
        verbatim_doc_comment,
        default_value_t = TestType::Crypto,
        value_parser = clap::builder::PossibleValuesParser::new(["crypto", "plaintext", "bidir"])
            .map(|s| s.parse::<TestType>().unwrap()),
    )]
    test_type: TestType,

    /// How many packets to send in total
    #[arg(long, default_value_t = 10)]
    packet_count: usize,

    /// Whether to build NepTUN and xray or rely on prebuilt binaries. Note: this does not apply to xtask. Default is to build
    #[arg(long, default_value_t = false)]
    nobuild: bool,

    /// Whether the generated graphs should be saved to disk. Ascii graphs are stored as .txt and "normal" graphs are stored as .png. Default is to not store
    #[arg(long, default_value_t = false)]
    save_output: bool,

    /// This parameter is directly passed through to NepTUN
    #[arg(long, default_value_t = false)]
    disable_drop_privileges: bool,

    /// Whether to show graphs in the terminal or in a separate window. Default is to show in separate window
    #[arg(long, default_value_t = false)]
    ascii: bool,
}

impl Cmd {
    pub fn run(&self) {
        let sh = Shell::new().expect("Failed to create shell object");
        let path_builder = PathGenerator::new(self.wg, self.test_type, self.packet_count);

        let results_dir = path_builder.results_dir();
        if !results_dir.exists() {
            std::fs::create_dir_all(results_dir).expect("Failed to create results folder");
        }
        let _ = std::fs::remove_file(path_builder.csv());
        let _ = std::fs::remove_file(path_builder.pcap());
        let _ = std::fs::remove_file(path_builder.png());
        let _ = std::fs::remove_file(path_builder.txt());

        let xray_res = self.run_xray(&sh, &path_builder);
        if let Err(e) = &xray_res {
            eprintln!("{e}");
        }

        let _ = self.stop_tcpdump(&sh);
        if let Err(e) = self.destroy_wg_adapter(&sh) {
            eprintln!("{e}");
        }

        if xray_res.is_ok() {
            let analyze_script = path_builder.analyze_script();
            let packet_count = self.packet_count.to_string();
            let base_path = path_builder.base();
            let analyze_res = match (self.save_output, self.ascii) {
                (true, true) => run_cmd!(sh, "{analyze_script} --packet-count {packet_count} --base-path {base_path} --save-output --ascii"),
                (true, false) => run_cmd!(sh, "{analyze_script} --packet-count {packet_count} --base-path {base_path} --save-output"),
                (false, true) => run_cmd!(sh, "{analyze_script} --packet-count {packet_count} --base-path {base_path} --ascii"),
                (false, false) => run_cmd!(sh, "{analyze_script} --packet-count {packet_count} --base-path {base_path}"),
            };
            if let Err(e) = analyze_res {
                eprintln!("{e}");
            }
        }
    }

    fn run_xray(&self, sh: &Shell, paths: &PathGenerator) -> Result<()> {
        if !self.nobuild {
            run_cmd!(
                sh,
                "cargo build --release --package neptun-cli --package xray"
            )?;
        }

        self.create_wg_adapter(sh, paths, self.disable_drop_privileges)?;
        let _ = self.start_tcpdump(sh, paths.pcap());

        let binary_dir = paths.binary_dir();
        let wg = self.wg.to_string();
        let test_type = self.test_type.to_string();
        let packet_count = self.packet_count.to_string();
        run_cmd!(
            sh,
            "sudo {binary_dir}/xray --wg {wg} --test-type {test_type} --packet-count {packet_count}"
        )?;

        Ok(())
    }

    fn create_wg_adapter(
        &self,
        sh: &Shell,
        paths: &PathGenerator,
        disable_drop_privileges: bool,
    ) -> Result<()> {
        match self.wg {
            Wg::NepTUN => {
                let binary_dir = paths.binary_dir();
                let disable_drop_privileges = match disable_drop_privileges {
                    true => " --disable-drop-privileges",
                    false => "",
                };
                run_cmd!(
                    sh,
                    "sudo {binary_dir}/neptun-cli {WG_NAME}{disable_drop_privileges}"
                )?;
            }
            Wg::LinuxNative => {
                run_cmd!(sh, "sudo ip link add dev {WG_NAME} type wireguard")?;
            }
            Wg::WireguardGo => {
                let wggo = cmd!(sh, "which wireguard-go")
                    .read()
                    .map_err(|e| Error::XShell {
                        cmd: "which wireguard-go",
                        inner: e,
                    })?;

                run_cmd!(sh, "sudo {wggo} {WG_NAME}")?;
            }
        }
        run_cmd!(sh, "sudo ip link set dev {WG_NAME} mtu 1420")?;
        run_cmd!(sh, "sudo ip link set dev {WG_NAME} up")?;

        // Disabling multicast is not strictly necessary but does make the pcap a bit leaner
        run_cmd!(sh, "sudo ip link set dev {WG_NAME} multicast off")?;

        Ok(())
    }

    fn start_tcpdump(&self, sh: &Shell, pcap_path: PathBuf) -> JoinHandle<()> {
        let sh = sh.clone();
        let packet_filter =
            format!("udp and (port {WG_PORT} or port {PLAINTEXT_PORT} or port {CRYPTO_PORT})");
        let handle = std::thread::spawn(move || {
            run_cmd!(
                sh,
                "sudo tcpdump -n --interface=any -w {pcap_path} {packet_filter}"
            )
            .expect("Failed to start tcpdump");
        });
        // Small sleep to make sure tcpdump has started before we continue
        // TODO(LLT-5969): wait for tcpdump to emit "listening on" instead of waiting fixed amount of time
        std::thread::sleep(std::time::Duration::from_secs(1));
        handle
    }

    fn stop_tcpdump(&self, sh: &Shell) -> Result<()> {
        run_cmd!(sh, "sudo killall --wait tcpdump")?;
        Ok(())
    }

    fn destroy_wg_adapter(&self, sh: &Shell) -> Result<()> {
        match self.wg {
            Wg::NepTUN => run_cmd!(sh, "killall -9 --wait neptun-cli"),
            Wg::LinuxNative | Wg::WireguardGo => run_cmd!(sh, "sudo ip link delete {WG_NAME}"),
        }?;
        Ok(())
    }
}
