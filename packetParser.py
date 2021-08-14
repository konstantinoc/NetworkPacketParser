"""
Use DPKT to read in a pcap file and print out the contents of the packets
This example is focused on the fields in the Ethernet Frame and IP packet
"""
import sys

import dpkt
import socket
import numpy as np
import matplotlib.pyplot as plt


def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def plot_cdf_packet_length(lengths_list):
    # sort the data in ascending order
    x = np.sort(lengths_list)

    # total packets in flow
    N = len(lengths_list)

    # get the cdf values of y
    y = np.arange(N) / float(N)

    # plotting
    plt.xlabel('packet size')
    plt.ylabel('CDF')

    plt.title('CDF Packet size')

    plt.grid(True)
    plt.plot(x, y, marker='o')
    plt.show()


def plot_cdf_flow_duration(dur_list):
    # sort the data in ascending order
    x = np.sort(dur_list)

    # total packets in flow
    N = len(dur_list)

    # get the cdf values of y
    y = np.arange(N) / float(N)

    # plotting
    plt.xlabel('Duration(Second)')
    plt.ylabel('CDF')

    plt.title('CDF Duration of flows')

    plt.grid(True)
    plt.plot(x, y, marker='x')
    plt.show()


def plot_cdf_flow_length(lengths_list):
    # sort the data in ascending order
    x = np.sort(lengths_list)

    # total packets in flow
    N = len(lengths_list)

    # get the cdf values of y
    y = np.arange(N) / float(N)

    # plotting
    plt.xlabel('Size(bytes)')
    plt.ylabel('CDF')

    plt.title('CDF Flows size')

    plt.grid(True)
    plt.plot(x, y, marker='o')
    plt.show()


def plot_packet_protocol(tcp, udp, icmp, arp, total):
    #
    x = ['TCP', 'UDP', 'ICMP', 'ARP']

    # get the cdf values of y
    y = [tcp / total, udp / total, icmp / total, arp / total]

    # plotting
    plt.xlabel('Protocol')
    plt.ylabel('Percentage')

    plt.title('Percentage of Packets per Protocol ')

    plt.grid(True)
    plt.bar(x, y)
    plt.show()


def analyze_packets(pcap):
    print("PLEASE WAIT\n")

    # initialize counters
    counter_total = 0
    counter_TCP = 0
    counter_UDP = 0
    counter_ICMP = 0
    counter_ARP = 0

    flows_len = []
    flows_duration = []
    lengths_list = []

    # initialize the dictionary
    # {hashValue : [total_packets_in_flow, first_timestamp, flow_duration, flow_length, [src_IP, dst_ip, src_port, dst_port]]}
    dictionary = {}

    for timestamp, buf in pcap:
        counter_total += 1
        eth = dpkt.ethernet.Ethernet(buf)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            # print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            if eth.data.__class__ == dpkt.arp.ARP:
                counter_ARP += 1
            continue

        ip = eth.data

        lengths_list.append(ip.len)

        if ip.p == dpkt.ip.IP_PROTO_ICMP:
            counter_ICMP += 1

        if ip.p == dpkt.ip.IP_PROTO_TCP or ip.p == dpkt.ip.IP_PROTO_UDP:
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                counter_TCP += 1
            else:
                if ip.p == dpkt.ip.IP_PROTO_UDP:
                    counter_UDP += 1

            # [src_IP, dst_ip, src_port, dst_port]
            packet_header = [inet_to_str(ip.src), inet_to_str(ip.dst), ip.data.sport, ip.data.dport]

            # header hash value
            hashed_header = hash(str(packet_header))

            # if packet is not the first of the flow
            if hashed_header in dictionary:
                dictionary[hashed_header][0] += 1
                dictionary[hashed_header][2] = timestamp-dictionary[hashed_header][1]
                dictionary[hashed_header][3] += ip.len

            # if the packet is the fisrt of the flow(new flow)
            else:
                dictionary[hashed_header] = [1, timestamp, 0, ip.len]
                dictionary[hashed_header].append(packet_header)

    print("############################")
    print("######    ANALYSIS    ######")
    print("############################\n")

    # remove flows with only one packet
    for item in dictionary.copy():
        if dictionary[item][0] == 1:
            dictionary.pop(item)

    for item in dictionary:
        flows_duration.append(dictionary[item][2])
        flows_len.append(dictionary[item][3])

    # print stats
    print('Flow Length:')
    plot_cdf_flow_length(flows_len)
    print('Max =', max(flows_len))
    print('Min =', min(flows_len))
    print('Avg = ', sum(flows_len) / len(flows_len))
    print()

    print('Flow Duration:')
    plot_cdf_flow_duration(flows_duration)
    print('Max =', max(flows_duration))
    print('Min =', min(flows_duration))
    print('Avg = ', sum(flows_duration) / len(flows_duration))
    print()

    print('Packet Length:')
    plot_cdf_packet_length(lengths_list)
    print('Max =', max(lengths_list))
    print('Min =', min(lengths_list))
    print('Avg = ', sum(lengths_list) / len(lengths_list))
    print()

    print('Protocols:')
    plot_packet_protocol(counter_TCP, counter_UDP, counter_ICMP, counter_ARP, counter_total)
    print('TCP = ', counter_TCP)
    print('UDP = ', counter_UDP)
    print('ICMP = ', counter_ICMP)
    print('ARP = ', counter_ARP)
    print()

    # for item in dictionary:
    #     print(item, dictionary[item])
    # print(len(dictionary))
    #


def open_pcap(file_name):
    with open(file_name, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        analyze_packets(pcap)


if __name__ == '__main__':
    file_name = sys.argv[1]
    open_pcap(file_name)
