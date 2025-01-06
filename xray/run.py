#!/usr/bin/env python3

import argparse
import os
import shlex
import subprocess
from enum import Enum
from pathlib import Path

from analyze import analyze
from paths import PathGenerator

WG_IFC_NAME = "xraywg1"


def run_command(cmd, capture_output=False):
    args = shlex.split(cmd)
    run = subprocess.run(args, capture_output=capture_output, check=True)
    return (run.stdout, run.stderr)


class Wireguard(Enum):
    NepTUN = 1
    WgGo = 2
    Native = 3
    BoringTun = 4

    def __str__(self):
        return self.name.lower()

    def from_str(s):
        if s is None or s.lower() == "neptun":
            return Wireguard.NepTUN
        if s.lower() == "wggo":
            return Wireguard.WgGo
        if s.lower() == "native":
            return Wireguard.Native
        if s.lower() == "boringtun":
            return Wireguard.BoringTun
        raise Exception(f"'{s}' is not a valid wireguard type")


class TestType(Enum):
    Crypto = 1
    Plaintext = 2

    def __str__(self):
        return self.name.lower()

    def from_str(s):
        if s is None or s.lower() == "crypto":
            return TestType.Crypto
        if s.lower() == "plaintext":
            return TestType.Plaintext
        raise Exception(f"'{s}' is not a valid test type")


def setup_wireguard(wg, build_neptun, disable_drop_privileges):
    if wg == Wireguard.Native:
        run_command(f"sudo ip link add dev {WG_IFC_NAME} type wireguard")
    elif wg == Wireguard.WgGo:
        wggo = (
            run_command("which wireguard-go", capture_output=True)[0]
            .strip()
            .decode("utf-8")
        )
        run_command(f"sudo {wggo} {WG_IFC_NAME}")
    elif wg == Wireguard.BoringTun:
        run_command(
            f"sudo ../target/release/boringtun-cli {WG_IFC_NAME}"
            + (" --disable-drop-privileges" if disable_drop_privileges else "")
        )
    else:
        if build_neptun:
            run_command(f"cargo build --release -p neptun-cli")
        run_command(
            f"sudo ../target/release/neptun-cli {WG_IFC_NAME}"
            + (" --disable-drop-privileges" if disable_drop_privileges else "")
        )
    run_command(f"sudo ip link set dev {WG_IFC_NAME} mtu 1420")
    run_command(f"sudo ip link set dev {WG_IFC_NAME} up")
    run_command(
        f"sudo ip link set dev {WG_IFC_NAME} multicast off"
    )  # Not strictly necessary but keeps the pcaps a bit cleaner


def start_tcpdump(pcap_path):
    return subprocess.Popen(
        [
            "sudo",
            "tcpdump",
            "-ni",
            "any",
            "-w",
            pcap_path,
            "udp and (port 41414 or port 52525 or port 63636)",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def run_xray(wg, test_type, count, build_xray, csv_path, pcap_path):
    if build_xray:
        run_command(f"cargo build --release -p xray")
    run_command(
        f"sudo ../target/release/xray --wg {wg} --test-type {test_type} --packet-count {count} --csv-path {csv_path} --pcap-path {pcap_path}"
    )


def stop_tcpdump(tcpdump):
    run_command(f"kill {tcpdump.pid}")


def destroy_wireguard(wg):
    if wg == Wireguard.NepTUN:
        run_command("sudo killall -9 neptun-cli")
    elif wg == Wireguard.BoringTun:
        run_command("sudo killall -9 boringtun-cli")
    else:
        run_command(f"sudo ip link delete {WG_IFC_NAME}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wg")
    parser.add_argument("--test-type")
    parser.add_argument("--count")
    parser.add_argument("--nobuild-neptun", action="store_true")
    parser.add_argument("--nobuild-xray", action="store_true")
    parser.add_argument("--save-output", action="store_true")
    parser.add_argument("--disable-drop-privileges", action="store_true")
    parser.add_argument("--ascii", action="store_true")
    args = parser.parse_args()

    wg = Wireguard.from_str(args.wg)
    test_type = TestType.from_str(args.test_type)
    count = int(args.count) if args.count is not None else 10
    assert count > 0, f"Count must be at least one, but got {count}"
    build_neptun = args.nobuild_neptun is False
    build_xray = args.nobuild_xray is False

    file_paths = PathGenerator(wg.name, test_type, count)

    Path("results/").mkdir(parents=True, exist_ok=True)
    try:
        os.remove(file_paths.csv())
        os.remove(file_paths.pcap())
        os.remove(file_paths.png())
        os.remove(file_paths.txt())
    except:  # noqa: E722
        pass

    setup_wireguard(wg, build_neptun, args.disable_drop_privileges)
    tcpdump = start_tcpdump(file_paths.pcap())

    succeeded = True
    try:
        run_xray(wg, test_type, count, build_xray, file_paths.csv(), file_paths.pcap())
    except:  # noqa: E722
        print("xray failed. Exiting...")
        succeeded = False
    finally:
        stop_tcpdump(tcpdump)
        destroy_wireguard(wg)

    if succeeded:
        analyze(
            file_paths,
            count,
            args.ascii,
            args.save_output,
        )


if __name__ == "__main__":
    main()
