from __future__ import print_function

from scapy.all import *
import argparse
import math
import time


def send_syn(dst_ip, src_port, recv_window, mss, verbose=False):
    """Sends a SYN packet and returns the SYN-ACK response.

       Args:
          dst_ip: The destination IP address.
          src_port: The source port number.
          recv_window: The receive window size to advertise in bytes.
          mss: The MSS to advertise in bytes.
          verbose: If True, print debug information.

        Returns:
          The SYN-ACK response packet.
    """
    ip = IP(dst=dst_ip)
    SYN = ip/TCP(sport=src_port, dport=80, flags="S", seq=42,
                 window=recv_window, options=[('MSS', mss)])
    if verbose:
        print(('Sending SYN packet to %s:%d. Advertising receive window size '
               '%d and MSS %d.') % (dst_ip, 80, recv_window, mss))
    SYNACK=sr1(SYN)
    if verbose:
        print('Received SYN-ACK:\n%s' % (SYNACK.show()))

    return SYNACK


def send_get_request(dst_ip, src_port, seq, ack, verbose=False):
    """Sends a GET request with a piggybacked ACK.

       Args:
          dst_ip; The destination IP address.
          src_port: The source port number.
          seq: The sequence number.
          ack: The ack number.
          verbose: If True, print debug information.

        Returns:
          A tuple of a list of the answered packets and a list of unanswered
          packets.
    """
    ip = IP(dst=dst_ip)
    get = 'GET / HTTP/1.1\r\n'
    GET = ip/TCP(sport=src_port, dport=80, flags="A", seq=seq, ack=ack) / get
    if verbose:
        print('Sending GET request to %s:%d.' % (dst_ip, 80))

    ans, unans = sr(GET)

    if verbose:
        print('Received GET response:')
        if ans is not None:
          print('Answered packets:')
          print(ans.show())
        else:
            print('No answered packets.')
        if unans is not None:
            print('Unanswered packets:')
            print(unans.show())
        else:
            print('No unanswered packets.')

    return ans, unans


def sniff_packets(src_port, timeout, verbose=False):
    """Sniffs for packets sent to SRC_PORT.

       Args:
          src_port: The source port number.
          timeout: The number of seconds to sniff for.
          verbose: If True, print debug information.

       Returns:
          The list of sniffed packets.
    """
    if verbose:
        print('Sniffing packets sent to port %d for %d seconds...' % (src_port,
                                                                      timeout))
    packets = sniff(filter="dst port 50000", timeout=timeout)

    if verbose:
        print('Sniffed packets:')
        for packet in packets:
            print(packet.show())

    return packets


def send_fin(dst_ip, src_port, verbose=False):
    """Sends a FIN packet to DST_IP.

       Args:
          dst_ip: The destination IP address.
          src_port: The source port number.
          verbose: If True, print debug information.

       Returns:
          The response to the FIN packet.
    """
    ip = IP(dst=dst_ip)
    FIN = ip/TCP(sport=src_port, dport=80, flags="FA")
    if verbose:
        print('Sending FIN packet to %s:%d.')
    FIN_response = sr1(FIN)
    if verbose:
        print('Received FIN response:\n%s' % (FIN_response.show()))

    return FIN_response


def main(args):
    if args.initial_delay is not None:
        print('Waiting %d seconds before starting...' % (args.initial_delay))
        time.sleep(args.initial_delay)
    SYNACK = send_syn(args.dst_ip, args.src_port, args.recv_window, args.mss,
                      args.verbose)
    ans, unans = send_get_request(args.dst_ip, args.src_port, SYNACK.ack,
                                  SYNACK.seq+1, args.verbose)
    all_packets = sniff_packets(args.src_port, args.timeout, args.verbose)
    FIN_response = send_fin(args.dst_ip, args.src_port, args.verbose)
    unique_packets = {}
    for i, packet in enumerate(all_packets):
        ip_datagram = packet.payload
        tcp_datagram = ip_datagram.payload
        data_len = ip_datagram.len - \
            (ip_datagram.ihl + tcp_datagram.dataofs) * 4
        seq = tcp_datagram.seq
        # print('Packet %d: seq=%d, len=%d' % (i, seq, data_len))
        if seq in unique_packets:
            unique_packets[seq] = max(data_len, unique_packets[seq])
        else:
            unique_packets[seq] = data_len
    seqs = sorted([seq for seq in unique_packets])
    for seq in seqs:
        print('seq=%d, len=%d' % (seq, unique_packets[seq]))
    icw_bytes = sum([unique_packets[seq] for seq in unique_packets])
    icw_segments = int(math.ceil(icw_bytes / float(args.mss)))
    print('ICW = %d bytes (%d segments)' % (icw_bytes, icw_segments))


if __name__=='__main__':
    parser = argparse.ArgumentParser(
      description='Estimate TCP initial window size')
    parser.add_argument('--dst_ip', type=str, default='www.google.com',
                        help='Destination IP address')
    parser.add_argument('--src_port', type=int, default=50000,
                        help='Source port')
    parser.add_argument('--mss', type=int, default=100,
                        help='MSS (in bytes)')
    parser.add_argument('--recv_window', type=int, default=(2**16)-1,
                        help='Receive window size')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Sniff timeout (in seconds)')
    parser.add_argument('--verbose', action='store_true', default=False,
                        help='Verbose mode')
    parser.add_argument('--initial_delay', type=int, default=None,
                        help=('Number of seconds to wait before establishing'
                              'connection'))
    args = parser.parse_args()
    main(args)
