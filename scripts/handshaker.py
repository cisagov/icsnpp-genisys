#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2022 Battelle Energy Alliance, LLC

# This was a quick one-off script I used to massage a mid-stream Genisys PCAP file into
# something that looks like a complete TCP session. It's not required at all
# for the operation of this plugin.

import argparse
import binascii
import itertools
import logging
import math
import os
import socket
import sys
import netaddr

from scapy.all import *
from collections import namedtuple

###################################################################################################
args = None
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()

Host = namedtuple("Host", ["mac", "ip"])


# From here https://pen-testing.sans.org/blog/2017/10/13/scapy-full-duplex-stream-reassembly
def full_duplex(p):
    sess = "Other"
    if 'Ether' in p:
        if 'IP' in p:
            if 'TCP' in p:
                sess = str(sorted(["TCP", p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport], key=str))
            elif 'UDP' in p:
                sess = str(sorted(["UDP", p[IP].src, p[UDP].sport, p[IP].dst, p[UDP].dport], key=str))
            elif 'ICMP' in p:
                sess = str(sorted(["ICMP", p[IP].src, p[IP].dst, p[ICMP].code, p[ICMP].type, p[ICMP].id], key=str))
            else:
                sess = str(sorted(["IP", p[IP].src, p[IP].dst, p[IP].proto], key=str))
        elif 'ARP' in p:
            sess = str(sorted(["ARP", p[ARP].psrc, p[ARP].pdst], key=str))
        else:
            sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
    return sess


###################################################################################################
# main
def main():
    global args

    parser = argparse.ArgumentParser(
        description='\n'.join(
            [
                'Do some stuff.',
            ]
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        usage='{} <arguments>'.format(script_name),
    )
    parser.add_argument(
        '--server',
        dest='server',
        action='store_true',
        default=False,
    )
    parser.add_argument(
        '--client',
        dest='client',
        action='store_true',
        default=False,
    )
    parser.add_argument(
        '--ip',
        dest='ip',
        nargs='*',
        type=str,
        default=[],
        required=False,
        help="IP(s) from PCAP(s)",
    )
    parser.add_argument('--verbose', '-v', action='count', default=1, help='Increase verbosity (e.g., -v, -vv, etc.)')
    parser.add_argument(
        '-i',
        '--input',
        dest='input',
        nargs='*',
        type=str,
        default=[],
        required=False,
        help="Input value(s)",
    )
    parser.add_argument(
        '-p',
        '--port',
        dest='port',
        type=int,
        default=10001,
    )
    parser.add_argument(
        '-b',
        '--bind',
        dest='bind',
        type=str,
        default='127.0.0.1',
    )
    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    if (not args.server and not args.client) or (args.server and args.client) or (len(args.ip) == 0):
        parser.print_help()
        exit(2)

    args.verbose = logging.CRITICAL - (10 * args.verbose) if args.verbose > 0 else 0
    logging.basicConfig(
        level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.debug(os.path.join(script_path, script_name))
    logging.debug("Arguments: {}".format(sys.argv[1:]))
    logging.debug("Arguments: {}".format(args))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    IP.payload_guess = []
    payloads = []
    longestLoad = 0

    for file in args.input:
        for session, packets in scapy.plist.PacketList(PcapReader(file)).sessions(full_duplex).items():
            logging.debug(session)
            for packet in packets:
                if IP in packet:
                    load = packet[Raw].load
                    longestLoad = max(longestLoad, len(load))
                    if (len(load) > 32) and (packet[IP].src in args.ip):
                        payloads.append(load[32:])

    logging.debug(f"As {'server' if args.server else 'client'} with {args.ip} I have {len(payloads)} payloads")

    if args.server:
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket to the port
        server_address = (args.bind, args.port)
        logging.info('starting up at {} over port {}'.format(*server_address))
        sock.bind(server_address)

        # Listen for incoming connections
        sock.listen(1)

        while True:
            # Wait for a connection
            logging.debug('Waiting for a connection')
            connection, client_address = sock.accept()
            try:
                logging.info(f'connection from {client_address}')

                # Receive the data in small chunks and retransmit it
                while True:
                    inData = connection.recv(longestLoad)
                    logging.debug(f'received {len(inData)} bytes')
                    if inData:
                        outData = payloads.pop(0)
                        logging.debug(f'sending {len(outData)} bytes')
                        connection.sendall(outData)
                    else:
                        break

            finally:
                # Clean up the connection
                logging.debug('Closing socket')
                connection.close()

    elif args.client:

        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        server_address = (args.bind, args.port)
        logging.info('connecting to {} over port {}'.format(*server_address))
        sock.connect(server_address)

        try:
            while len(payloads) > 0:
                outData = payloads.pop(0)
                logging.info(f'sending {len(outData)} bytes')
                sock.sendall(outData)
                inData = sock.recv(longestLoad)
                logging.info(f'received {len(inData)} bytes')

        finally:
            logging.debug('Closing socket')
            sock.close()


###################################################################################################
if __name__ == '__main__':
    main()
