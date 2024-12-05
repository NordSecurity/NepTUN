import csv
import math
from functools import reduce

import matplotlib as mpl  # type: ignore
import matplotlib.pyplot as plt  # type: ignore
import mpl_ascii  # type: ignore
from paths import PathGenerator


def analyze(paths, count, ascii, save_output):
    Analyzer(paths, count, ascii, save_output)


def parse_int(val):
    if val is None or val == "":
        return None
    else:
        return int(val)


class PacketInfo:
    def __init__(self, csv_row):
        self.recv_index = parse_int(csv_row[0])
        self.send_ts = int(csv_row[1])
        self.pre_wg_ts = parse_int(csv_row[2])
        self.post_wg_ts = parse_int(csv_row[3])
        self.recv_ts = parse_int(csv_row[4])

    def get_latencies(self):
        pre_wg = self.get_latency(self.send_ts, self.pre_wg_ts)
        post_wg = self.get_latency(self.pre_wg_ts, self.post_wg_ts)
        recv = self.get_latency(self.post_wg_ts, self.recv_ts)
        total = self.get_latency(self.send_ts, self.recv_ts)
        return (pre_wg, post_wg, recv, total)

    def get_latency(self, left, right):
        if left is not None and right is not None:
            return right - left
        else:
            return None


class CsvData:
    def __init__(self, csv_path):
        self.packets = []

        with open(csv_path, newline="") as csvfile:
            reader = csv.reader(csvfile, delimiter=",")
            next(reader)  # skip header row
            for row in reader:
                packet_info = PacketInfo(row)
                self.packets.append(packet_info)


class Analyzer:
    def __init__(
        self, paths: PathGenerator, count, ascii_output, save_output
    ):
        self.count = count
        self.csv_data = CsvData(paths.csv())

        graphs = [
            self.ordering_pie_chart,
            self.packet_ordering,
            self.dropped_packets,
            self.packet_latency,
            self.packet_funnel,
        ]

        if ascii_output:
            mpl_ascii.AXES_WIDTH = 70
            mpl_ascii.AXES_HEIGHT = 25
            mpl.use("module://mpl_ascii")
            # remove pie chart graph because it's not supported
            graphs.pop(0)

            rows, cols = len(graphs), 1
            pad = 0
        else:
            rows, cols = math.ceil(len(graphs) / 2), 2
            pad = 1

        fig, ax = plt.subplots(nrows=rows, ncols=cols)
        fig.tight_layout(pad=pad)

        for i, draw_fn in enumerate(graphs):
            draw_fn(self._get_axis(ax, i, cols))

        if save_output:
            output_file = paths.txt() if ascii_output else paths.png()
            plt.savefig(output_file)
        plt.show()

    def _get_axis(self, ax, i, cols):
        if cols == 1:
            return ax[i]
        row = i // cols
        col = i % cols
        return ax[row, col]

    def ordering_pie_chart(self, ax):
        in_order = count_ordered(self.csv_data.packets, self.count)
        dropped = reduce(
            lambda count, packet: count + (1 if packet.recv_index is None else 0),
            self.csv_data.packets,
            0,
        )
        reordered = self.count - in_order - dropped
        data = []
        labels = []
        if in_order > 0:
            data.append(in_order)
            labels.append(f"In order ({round((in_order/self.count) * 100, 2)}%)")
        if reordered > 0:
            data.append(reordered)
            labels.append(f"Reordered ({round((reordered/self.count) * 100, 2)}%)")
        if dropped > 0:
            data.append(dropped)
            labels.append(f"Dropped ({round((dropped/self.count) * 100, 2)}%)")
        ax.set_title("In order/reordered/dropped")
        ax.pie(data, labels=labels)

    def packet_ordering(self, ax):
        data = list(map(lambda p: p.recv_index, self.csv_data.packets))
        ax.set_title("Packet order")
        ax.set_xlabel("Received order")
        ax.set_ylabel("Packet index")
        ax.plot(data)

    def packet_latency(self, ax):
        data = list(map(lambda pi: pi.get_latencies(), self.csv_data.packets))
        pre_wg = []
        post_wg = []
        recv = []
        for l in data:  # noqa: E741 (ambiguous name)
            if l[0] is not None:
                pre_wg.append(l[0])
            if l[1] is not None:
                post_wg.append(l[1])
            if l[2] is not None:
                recv.append(l[2])

        ax.set_title("Latency")
        ax.set_xlabel("Latency (Microseconds)")
        ax.set_ylabel("Count")
        ax.hist(
            [pre_wg, post_wg, recv],
            label=["PreWG", "PostWG", "Recv"],
            color=["orange", "green", "blue"],
            stacked=True,
            bins=15,
        )
        ax.legend()

    def dropped_packets(self, ax):
        if self.count >= 100:
            num_buckets = 100
        elif self.count >= 10:
            num_buckets = 10
        else:
            num_buckets = self.count

        pre_wg = []
        post_wg = []
        recv = []
        for i, packet in enumerate(self.csv_data.packets):
            if packet.pre_wg_ts is None:
                pre_wg.append(i)
            if packet.post_wg_ts is None:
                post_wg.append(i)
            if packet.recv_ts is None:
                recv.append(i)

        ax.set_title("Dropped packets")
        ax.set_xlabel("Index")
        ax.set_ylabel("Count")
        ax.hist(
            [pre_wg, post_wg, recv],
            label=["PreWG", "PostWG", "Recv"],
            color=["orange", "green", "blue"],
            stacked=True,
            bins=num_buckets,
        )
        ax.legend()

    def packet_funnel(self, ax):
        count = self.count
        before_wg = 0
        after_wg = 0
        recv = 0
        for p in self.csv_data.packets:
            before_wg += 1 if p.pre_wg_ts is not None else 0
            after_wg += 1 if p.post_wg_ts is not None else 0
            recv += 1 if p.recv_ts is not None else 0
        categories = [
            f"Count ({count})",
            f"Before wg ({before_wg})",
            f"After_wg ({after_wg})",
            f"Recv ({recv})",
        ]
        values = [self.count, before_wg, after_wg, recv]
        ax.bar(categories, values, color="blue", width=0.4)


# This counts in-order packets by looking at series of successive packets
# the length of the sequence could be considered a number of packest in order
# however, if the first packet of the sequence is not in order, then the length of the sequence - 1 is in order
# this last step also takes care of sequences of length 1 (unless the packet is where it's supposed to be)
def count_ordered(data, count):
    if len(data) == 0:
        return 0
    indices = list(map(lambda p: p.recv_index, data))
    ordered = 0
    range_good_start = indices[0] == 1
    range_len = 1
    prev = indices[0]
    for i in range(1, len(indices)):
        if indices[i] is None:
            continue
        elif indices[i] == prev + 1:
            range_len += 1
        else:
            ordered += range_len - (0 if range_good_start else 1)
            range_good_start = indices[i] == i
            range_len = 1
        prev = indices[i]
    ordered += range_len - (0 if range_good_start else 1)
    return ordered
