import csv
import math
import matplotlib.pyplot as plt  # type: ignore
from functools import reduce
from scapy.all import PcapReader  # type: ignore
from scapy.layers.inet import UDP  # type: ignore


def analyze(csv_path, pcap_path, count, test_type):
    Analyzer(csv_path, pcap_path, count, test_type)


class CsvData:
    def __init__(self, csv_path):
        self.indices = []
        self.timestamps = []
        self.latencies = []
        self.min_latency = -1
        self.max_latency = -1

        with open(csv_path, newline="") as csvfile:
            reader = csv.reader(csvfile, delimiter=",", quotechar="|")
            next(reader)
            for row in reader:
                if len(row[0]) > 0:
                    self.indices.append(int(row[0]))
                send_ts = int(row[1])
                if len(row[2]) > 0:
                    recv_ts = int(row[2])
                else:
                    recv_ts = -1
                self.timestamps.append((send_ts, recv_ts))
                if recv_ts >= 0:
                    latency = recv_ts - send_ts
                    self.latencies.append(latency)
                    if self.min_latency < 0 or latency < self.min_latency:
                        self.min_latency = latency
                    if self.max_latency < 0 or latency > self.max_latency:
                        self.max_latency = latency


class PcapData:
    def __init__(self, pcap_path, test_type):
        self.before_wg_packets = []
        self.after_wg_packets = []
        with PcapReader(pcap_path) as pcap_reader:
            for pkt in pcap_reader:
                if not pkt.haslayer(UDP):
                    continue

                if test_type == "crypto" and pkt.sport == 63636:
                    if pkt.dport == 41414:
                        self.before_wg_packets.append(pkt)
                    elif pkt.dport == 52525:
                        self.after_wg_packets.append(pkt)
                elif test_type == "pt" and pkt.dport == 63636:
                    if pkt.sport == 52525:
                        self.before_wg_packets.append(pkt)
                    elif pkt.sport == 41414:
                        self.after_wg_packets.append(pkt)


class Analyzer:
    def __init__(self, csv_name, pcap_name, count, test_type):
        self.count = count
        self.csv_data = CsvData(csv_name)
        self.pcap_data = PcapData(pcap_name, test_type)

        graphs = [
            self.ordering_pie_chart,
            self.packet_ordering,
            self.dropped_packets,
            self.packet_latency,
            self.packet_funnel,
        ]
        rows = math.ceil(len(graphs) / 2)

        fig, ax = plt.subplots(nrows=rows, ncols=2)
        fig.tight_layout(pad=1)

        for i, fn in enumerate(graphs[0:rows]):
            fn(ax[i, 0])
        for i, fn in enumerate(graphs[rows:]):
            fn(ax[i, 1])

        plt.show()

    def ordering_pie_chart(self, ax):
        in_order = count_ordered(self.csv_data.indices, self.count)
        dropped = reduce(
            lambda count, e: count + (1 if e == 0 else 0), self.csv_data.indices, 0
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
        y_axis = [None]
        x_axis = [0]
        for iter, index in enumerate(self.csv_data.indices):
            if self.csv_data.timestamps[iter][1] >= 0:
                y_axis.append(self.csv_data.indices[iter])
            else:
                y_axis.append(None)
            x_axis.append(iter + 1)
        ax.set_title("Packet order")
        ax.set_xlabel("Received order")
        ax.set_ylabel("Packet index")
        ax.plot(x_axis, y_axis)

    def packet_latency(self, ax):
        millisec = 1000
        sec = 1000 * millisec
        if self.csv_data.min_latency > sec:
            divisor = sec
            timeunit = "Seconds"
        elif self.csv_data.min_latency > millisec:
            divisor = millisec
            timeunit = "Milliseconds"
        else:
            divisor = 1
            timeunit = "Microseconds"

        num_buckets = 15
        bucket_size = int(
            (self.csv_data.max_latency - self.csv_data.min_latency) / (num_buckets - 1)
        )
        buckets = []
        for latency in self.csv_data.latencies:
            bucket_index = int((latency - self.csv_data.min_latency) / bucket_size)
            buckets.append(
                (self.csv_data.min_latency + (bucket_index * bucket_size)) / divisor
            )
        ax.set_title("Latency")
        ax.set_xlabel(f"Latency ({timeunit})")
        ax.set_ylabel("Count")
        ax.hist(buckets, color="blue", bins=num_buckets)

    def dropped_packets(self, ax):
        if self.count >= 100:
            num_buckets = 100
        elif self.count >= 10:
            num_buckets = 10
        else:
            num_buckets = self.count
        bucket_size = int(self.count / (num_buckets - 1))
        buckets = []
        for iter, index in enumerate(self.csv_data.indices):
            if self.csv_data.timestamps[iter][1] < 0:
                bucket_index = int(iter / bucket_size)
                buckets.append(bucket_index * bucket_size)
        ax.set_title("Dropped packets")
        ax.set_xlabel("Index")
        ax.set_ylabel("Count")
        ax.hist(buckets, color="blue", bins=num_buckets)

    def dropped_packets2(self, ax):
        data = []
        for iter, index in enumerate(self.csv_data.indices):
            if self.csv_data.timestamps[iter][1] < 0:
                data.append(index)
        ax.set_title("Dropped packets 2")
        ax.set_xlabel("Packet index")
        ax.set_ylabel("Count")
        ax.plot(data)

    def packet_funnel(self, ax):
        count = self.count
        before_wg = len(self.pcap_data.before_wg_packets)
        after_wg = len(self.pcap_data.after_wg_packets)
        recv = len(list(filter(lambda x: x > 0, self.csv_data.indices)))
        categories = [
            f"Count ({count})",
            f"before wg ({before_wg})",
            f"after_wg ({after_wg})",
            f"Recv ({recv})",
        ]
        values = [self.count, before_wg, after_wg, recv]
        plt.bar(categories, values, color="blue", width=0.4)


# This counts in-order packets by looking at series of successive packets
# the length of the sequence could be considered a number of packest in order
# however, if the first packet of the sequence is not in order, then the length of the sequence - 1 is in order
# this last step also takes care of sequences of length 1 (unless the packet is where it's supposed to be)
def count_ordered(data, count):
    if len(data) == 0:
        return 0
    ordered = 0
    range_good_start = data[0] == 1
    range_len = 1
    prev = data[0]
    for i in range(1, len(data)):
        if data[i] == 0:
            continue
        elif data[i] == prev + 1:
            range_len += 1
        else:
            ordered += range_len - (0 if range_good_start else 1)
            range_good_start = data[i] = i
            range_len = 1
        prev = data[i]
    ordered += range_len - (0 if range_good_start else 1)
    return ordered
