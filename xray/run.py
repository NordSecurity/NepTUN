#!/usr/bin/env python3

import argparse
import os
import shlex
import subprocess
from analyze import analyze
from enum import Enum
from pathlib import Path

WG_IFC_NAME = "xraywg1"


def run_command(cmd, capture_output=False):
    args = shlex.split(cmd)
    run = subprocess.run(args, capture_output=capture_output,check=True)
    return (run.stdout, run.stderr)


def get_csv_name(wg, test_type, count):
    return f"results/xray_metrics_{wg.lower()}_{test_type}_{count}.csv"


def get_pcap_name(wg, test_type, count):
    return f"results/{WG_IFC_NAME}_{wg.lower()}_{test_type}_{count}.pcap"


class Wireguard(Enum):
    NepTUN = 1
    WgGo = 2
    Native = 3
    BoringTun = 4

    def from_str(s):
        if s is None or s.lower() == "neptun":
            return Wireguard.NepTUN
        elif s is not None and s.lower() == "wggo":
            return Wireguard.WgGo
        elif s is not None and s.lower() == "native":
            return Wireguard.Native
        elif s is not None and s.lower() == "boringtun":
            return Wireguard.BoringTun
        else:
            raise Exception(f"{s} is not a valid wireguard type")


def setup_wireguard(wg, build_neptun):
    if wg == Wireguard.Native:
        run_command(f"sudo ip link add dev {WG_IFC_NAME} type wireguard")
    elif wg == Wireguard.WgGo:
        wggo = (
            run_command("which wireguard", capture_output=True)[0]
            .strip()
            .decode("utf-8")
        )
        run_command(f"sudo {wggo} {WG_IFC_NAME}")
    elif wg == Wireguard.BoringTun:
        run_command(f"sudo ../target/release/boringtun-cli {WG_IFC_NAME}")
    else:
        if build_neptun:
            run_command(f"cargo run --release -p neptun-cli -- {WG_IFC_NAME}")
        else:
            run_command(f"sudo ../target/release/neptun-cli {WG_IFC_NAME}")
    run_command(f"sudo ip link set dev {WG_IFC_NAME} up")
    run_command(
        f"sudo ip link set dev {WG_IFC_NAME} multicast off"
    )  # Not strictly necessary but keeps the pcaps a bit cleaner


def start_tcpdump(pcap_name):
    return subprocess.Popen(
        ["sudo", "tcpdump", "-ni", "any", "-w", pcap_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def run_xray(wg, test_type, count, build_xray):
    if build_xray:
        run_command(
            f"cargo run --release -- {wg} {test_type} {count} {get_csv_name(wg, test_type, count)}"
        )
    else:
        run_command(f"sudo ../target/release/xray {wg} {test_type} {count} {get_csv_name(wg, test_type, count)}")


def stop_tcpdump(tcpdump):
    run_command(f"kill {tcpdump.pid}")


def destroy_wireguard(wg):
    if wg == Wireguard.NepTUN:
        run_command("killall -9 neptun-cli")
    elif wg == Wireguard.BoringTun:
        run_command("killall -9 boringtun-cli")
    else:
        run_command(f"sudo ip link delete {WG_IFC_NAME}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wg")
    parser.add_argument("--test-type")
    parser.add_argument("--count")
    parser.add_argument("--nobuild-neptun", action="store_true")
    parser.add_argument("--nobuild-xray", action="store_true")
    args = parser.parse_args()

    wg = Wireguard.from_str(args.wg)
    test_type = args.test_type.lower() if args.test_type is not None else "crypto"
    assert test_type in [
        "crypto",
        "plaintext",
    ], f"Invalid test type '{test_type}'. Valid options are 'crypto' and 'plaintext'"
    count = int(args.count) if args.count is not None else 10
    assert count > 0, f"Count must be at least one, but got {count}"
    build_neptun = args.nobuild_neptun is False
    build_xray = args.nobuild_xray is False

    Path("results/").mkdir(parents=True, exist_ok=True)
    try:
        os.remove(get_csv_name(wg.name, test_type, count))
        os.remove(get_pcap_name(wg.name, test_type, count))
    except:  # noqa: E722
        pass

    setup_wireguard(wg, build_neptun)
    tcpdump = start_tcpdump(get_pcap_name(wg.name, test_type, count))

    succeeded = True
    try:
        run_xray(wg.name, test_type, count, build_xray)
    except:  # noqa: E722
        print("xray failed. Exiting...")
        succeeded = False
    finally:
        stop_tcpdump(tcpdump)
        destroy_wireguard(wg)

    if succeeded:
        analyze(
            get_csv_name(wg.name, test_type, count),
            get_pcap_name(wg.name, test_type, count),
            count,
            test_type,
        )


if __name__ == "__main__":
    main()
