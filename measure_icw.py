from __future__ import print_function

from scapy.all import *
import argparse
import json
import math
import time
import tqdm


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
    SYNACK=sr1(SYN, verbose=verbose, timeout=10)
    if verbose:
        if SYNACK is not None:
            print('Received SYN-ACK:\n%s' % (SYNACK.show(dump=True)))
        else:
            print('Could not establish a connection to %s.' % (dst_ip))

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
    get = 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % (dst_ip)
    GET = ip/TCP(sport=src_port, dport=80, flags="A", seq=seq, ack=ack) / get
    if verbose:
        print('Sending GET request to %s:%d.' % (dst_ip, 80))

    ans, unans = sr(GET, verbose=verbose, timeout=5)

    if verbose:
        print('Received GET response:')
        if ans is not None:
          print('Answered packets:')
          ans.show()
        else:
            print('No answered packets.')
        if unans is not None:
            print('Unanswered packets:')
            unans.show()
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
    packets = sniff(filter='dst port 50000', timeout=timeout)

    """
    if verbose:
        print('Sniffed packets:')
        for packet in packets:
            packet.show())
    """

    return packets


def send_fin(dst_ip, src_port, seq, ack, verbose=False):
    """Sends a FIN packet to DST_IP.

       Args:
          dst_ip: The destination IP address.
          src_port: The source port number.
          verbose: If True, print debug information.
    """
    ip = IP(dst=dst_ip)
    FIN = ip/TCP(sport=src_port, dport=80, flags="FA", seq=seq, ack=ack)
    if verbose:
        print('Sending FIN packet to %s:%d.' % (dst_ip, 80))
    FIN_response = sr1(FIN, verbose=verbose)
    if verbose:
        if FIN_response is None:
            print('No FIN response.')
        else:
            print('Received FIN response:\n%s' % (FIN_response.show(dump=True)))

    if verbose:
        print('Acknowledging FIN from %s:%d.' % (dst_ip, 80))
    if FIN_response is not None:
        ACK = ip/TCP(sport=src_port, dport=80, flags="A", seq=FIN_response.ack,
                     ack=FIN_response.seq+1)
        sr1(ACK, verbose=verbose)


def measure_icw(dst_ip, src_port, recv_window, mss, timeout, verbose):
    SYNACK = send_syn(dst_ip, src_port, recv_window, mss, verbose)
    if SYNACK is None:
        return (None, None)
    ans, unans = send_get_request(dst_ip, src_port, SYNACK.ack,
                                  SYNACK.seq+1, verbose)
    if ans is None and unans is None:
        return (None, None)
    all_packets = sniff_packets(src_port, timeout, verbose)
    unique_packets = {}
    for i, packet in enumerate(all_packets):
        try:
            ip_datagram = packet.payload
            tcp_datagram = ip_datagram.payload
            data_len = ip_datagram.len - \
            (ip_datagram.ihl + tcp_datagram.dataofs) * 4
            payload = tcp_datagram.payload.show(dump=True)
            unique_packets[payload] = data_len
        except Exception as e:
            continue
        """
        if i == len(all_packets)-1:
            send_fin(args.dst_ip, args.src_port, packet.ack, packet.seq+1,
                     args.verbose)
        """
    received_http_ok = False
    for payload in unique_packets:
        if 'HTTP/1.1 200 OK' in payload:
            received_http_ok = True
            break
    if not received_http_ok:
        return (None, None)
    elif verbose:
        for payload in unique_packets:
            print(payload)

    icw_bytes = sum([unique_packets[payload] for payload in unique_packets])
    icw_segments = int(math.ceil(icw_bytes / float(args.mss)))
    return (icw_bytes, icw_segments)


def main(args):

    if args.initial_delay is not None:
        print('Waiting %d seconds before starting...' % (args.initial_delay))
        time.sleep(args.initial_delay)

    if args.dst_ip is not None:
        (icw_bytes, icw_segments) = measure_icw(args.dst_ip, args.src_port,
                                                args.recv_window,
                                                args.mss, args.timeout,
                                                args.verbose)
        if icw_bytes is None or icw_segments is None:
            print('Could not get ICW for %s' % (args.dist_ip))
            return
        print('%s ICW = %d bytes (%d segments)' % (args.dst_ip, icw_bytes,
                                                   icw_segments))
    elif args.input_file is not None:
        results = {}
        with open(args.input_file, 'r') as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                dst_ip = line.strip()
                results[dst_ip] = []
                for j in range(5):
                    time.sleep(60)
                    (icw_bytes, icw_segments) = measure_icw(dst_ip,
                                                            args.src_port,
                                                            args.recv_window,
                                                            args.mss,
                                                            args.timeout,
                                                            args.verbose)
                    if icw_bytes is None or icw_segments is None:
                        results[dst_ip].append(None)
                        continue
                    results[dst_ip].append(icw_segments)
                    print(('[%d/5 | %d/%d] %s ICW = %d bytes '
                           '(%d segments)') % (j, i+1, len(lines), dst_ip,
                                               icw_bytes,
                                               icw_segments))

        print(json.dumps(results, indent=4))

if __name__=='__main__':
    parser = argparse.ArgumentParser(
      description='Estimate TCP initial window size')
    parser.add_argument('--dst_ip', type=str, default=None,
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
    parser.add_argument('--input_file', type=str, default=None,
                        help='File with list of IPs to measure')
    args = parser.parse_args()

    if args.dst_ip is not None and args.input_file is not None:
        raise ValueError('Only one of --dst_ip and --input_file may be set.')
    elif args.dst_ip is None and args.input_file is None:
        raise ValueError('One of --dst_ip and --input_file must be set.')

    main(args)
