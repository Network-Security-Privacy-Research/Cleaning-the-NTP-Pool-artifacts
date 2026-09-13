#!/usr/bin/env python3
import ipaddress
import argparse
import logging
import random
import string
import json
import time

import dns.resolver
from scapy.all import IPv6, sr1, UDP, NTP, RandShort


logging.basicConfig(level=logging.DEBUG)


def checkArgs(n):
    try:
        ipaddress.IPv6Network(n)

    except Exception as e:
        logging.fatal(f"Error parsing {n} as an IPv6 network: {e}")


def getRandomSourceAddress(network):
    logging.debug(f"Getting a random source address in {network}")

    net = ipaddress.IPv6Network(network)

    # Get first address in range
    firstAddress = net.network_address

    # Number of random bits we need
    needBits = 128 - net.prefixlen

    # Get integer with needBits random bits
    randBits = random.getrandbits(needBits)

    randAddr = firstAddress + randBits

    return randAddr


def queryServer(serverAddr, net, prefix, minTTL, maxTTL, timeout):

    # init probe tgt json object
    j = {
        'start_time' : int(time.time()),
        'dst_ip': serverAddr,
        'min_ttl': minTTL,
        'max_ttl': maxTTL,
        'timeout' : timeout,
        'hops': []
    }
    with open(f"{prefix}-ntp-traceroute-{int(time.time())}.jsonl",
              "a") as f:
        for ttl in range(minTTL, maxTTL):
            # Get new src IP and src port for this dest/TTL combo
            src = getRandomSourceAddress(net)
            randPort = int(RandShort())

            # this just prevents us from looking like some common protocol when manually inspecting
            if randPort < 2048:
                randPort += 2048

            #hop json obj
            hop = {
                'ttl': ttl,
                'src_ip': str(src),
                'src_port': randPort,
                'ntp_reply' : False
            }

            pkt = IPv6(dst=serverAddr, src=str(src), hlim=ttl) / UDP(sport=randPort, dport=123) / NTP()
            logging.info(f"Querying [{src}]:{randPort} --> [{serverAddr}]:123 @ TTL={ttl}")
            p = sr1(pkt, timeout=timeout)
            if p and NTP in p:
                logging.info("Got an NTP response, stop probing now")
                hop["ntp_reply"] = True
                j["hops"].append(hop)
                break
            else:
                logging.debug("Didn't find NTP response; TTL++")

            j["hops"].append(hop)
        f.write(f"{json.dumps(j)}\n")



def readServerAddresses(fname):
    AAAA = []
    with open(fname) as f:
        for line in f:
            l = line.strip()
            AAAA.append(l)

    return AAAA


def main(args):
    ntpServerAddrs = readServerAddresses(args.fname)
    logging.debug(f"Retrieved {len(ntpServerAddrs)} addresses")

    for server in ntpServerAddrs:
        queryServer(server, args.network, args.prefix, args.minTTL, args.maxTTL, args.timeout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--network", type=str, required=True,
                        help="IPv6 network to draw random addresses out of")
    parser.add_argument("-f", "--fname", type=str, required=True,
                        help="IPv6 NTP server addresses")
    parser.add_argument("-p", "--prefix", type=str, help="Prefix for probed address output file", required=True)
    parser.add_argument("-m", "--minTTL", type=int, default=1, help="Minimum TTL to use when NTP tracing to targets")
    parser.add_argument("-x", "--maxTTL", type=int, default=32, help="Maximum TTL to use when NTP tracing to targets")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Timeout to wait for NTP response")
    args = parser.parse_args()

    checkArgs(args.network)

    main(args)
