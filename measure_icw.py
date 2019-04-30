from __future__ import print_function

from scapy.all import *
import argparse
import json
import math
import time
import tqdm


def send_syn(dst_ip, src_port, recv_window, mss, timeout, verbose=False):
    """Sends a SYN packet and returns the SYN-ACK response.

       Args:
          dst_ip: The destination IP address.
          src_port: The source port number.
          recv_window: The receive window size to advertise in bytes.
          mss: The maximum segment size to advertise in bytes.
          timeout: The send timeout in seconds.
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
    SYNACK=sr1(SYN, verbose=verbose, timeout=timeout)
    if verbose:
        if SYNACK is not None:
            print('Received SYN-ACK:\n%s' % (SYNACK.show(dump=True)))
        else:
            print('Could not establish a connection to %s.' % (dst_ip))

    return SYNACK


def send_get_request(dst_ip, src_port, seq, ack, timeout, verbose=False):
    """Sends a GET request with a piggybacked ACK.

       Args:
          dst_ip; The destination IP address.
          src_port: The source port number.
          seq: The sequence number.
          ack: The ack number.
          timeout: The send timeout in seconds.
          verbose: If True, print debug information.

        Returns:
          The list of packets sent in response to the GET request.
    """
    ip = IP(dst=dst_ip)
    get = 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % (dst_ip)
    GET = ip/TCP(sport=src_port, dport=80, flags="A", seq=seq, ack=ack) / get
    if verbose:
        print('Sending GET request to %s:%d.' % (dst_ip, 80))
    send(GET, verbose=verbose)
    packets = sniff(filter='dst port %d' % (src_port), timeout=timeout)
    if verbose:
        print('Received %d packets' % (len(packets)))
    return packets


def send_fin(dst_ip, src_port, seq, ack, verbose=False):
    """Sends a FIN packet to DST_IP.

       Args:
          dst_ip: The destination IP address.
          src_port: The source port number.
          seq: The sequence number.
          ack: The ack number.
          verbose: If True, print debug information.
    """
    ip = IP(dst=dst_ip)
    FIN = ip/TCP(sport=src_port, dport=80, flags="FA", seq=seq, ack=ack)
    if verbose:
        print('Sending FIN packet to %s:%d.' % (dst_ip, 80))
    send(FIN, verbose=verbose)
    packets = sniff(filter='dst port %d' % (src_port), timeout=10)
    for packet in packets:
        if 'F' in str(packet.flags):
            if verbose:
                print(('Received FIN packet from %s:%d,'
                       'sending response') % (dst_ip, 80))
            ACK = ip/TCP(sport=src_port, dport=80, flags="A",
                         seq=packet.ack, ack=packet.seq+1)
            send(ACK, verbose=verbose)


def measure_icw(dst_ip, src_port, recv_window, mss, timeout, verbose):
    """Measures the initial congestion window of the server located at DST_IP.

       Args:
          dst_ip: The destination IP address.
          src_port: The source port number.
          seq: The sequence number.
          ack: The ack number.
          recv_window: The receive window size to advertise in bytes.
          mss: The maximum segment size to advertise in bytes.
          verbose: If True, print debug information.

       Returns:
          A tuple of (initial window size in bytes,
                      initial window size in segments).

    """
    SYNACK = send_syn(dst_ip, src_port, recv_window, mss, timeout, verbose)
    if SYNACK is None:
        return (None, None)
    packets = send_get_request(dst_ip, src_port, SYNACK.ack,
                               SYNACK.seq+1, verbose)
    unique_packets = {}
    for i, packet in enumerate(packets):
        try:
            ip_datagram = packet.payload
            tcp_datagram = ip_datagram.payload
            data_len = ip_datagram.len - \
                (ip_datagram.ihl + tcp_datagram.dataofs) * 4
            payload = tcp_datagram.payload.show(dump=True)
            if verbose:
                print('Packet %d: %s' % (i, payload))
            if payload in unique_packets:
                break
            else:
                unique_packets[payload] = data_len
        except Exception as e:
            continue

    if len(packets) == 0:
        return (None, None)

    send_fin(dst_ip, src_port, packets[i-1].ack, packets[i-1].seq+1,
             verbose)
    icw_bytes = sum([unique_packets[payload] for payload in unique_packets])
    icw_segments = int(math.ceil(icw_bytes / float(args.mss)))
    return (icw_bytes, icw_segments)


def main(args):
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
                results[dst_ip] = {}
                results[dst_ip]['Bytes'] = []
                results[dst_ip]['Segments'] = []
                for j in range(args.num_trials):
                    (icw_bytes, icw_segments) = measure_icw(dst_ip,
                                                            args.src_port+j,
                                                            args.recv_window,
                                                            args.mss,
                                                            args.timeout,
                                                            args.verbose)
                    if icw_bytes is None or icw_segments is None:
                        results[dst_ip]['Bytes'].append(None)
                        results[dst_ip]['Segments'].append(None)
                        continue
                    results[dst_ip]['Bytes'].append(icw_bytes)
                    results[dst_ip]['Segments'].append(icw_segments)
                    print(('[%d/5 | %d/%d] %s ICW = %d bytes '
                           '(%d segments)') % (j+1, i+1, len(lines), dst_ip,
                                               icw_bytes,
                                               icw_segments))
                    if j < args.num_trials - 1:
                        print('')
                        print('-' * 80)
                print('')
                print('=' * 80)

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
    parser.add_argument('--num_trials', type=int, default=5,
                        help='The number of trials to run each experiment for.')
    args = parser.parse_args()

    if args.dst_ip is not None and args.input_file is not None:
        raise ValueError('Only one of --dst_ip and --input_file may be set.')
    elif args.dst_ip is None and args.input_file is None:
        raise ValueError('One of --dst_ip and --input_file must be set.')

    main(args)
