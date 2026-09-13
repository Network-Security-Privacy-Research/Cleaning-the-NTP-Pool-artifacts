# Artifact 1 — Nonced IPv6 NTP probing

> The code necessary to generate nonced IPv6 NTP queries on a per IPv6 Hop
> Limit and NTP server combination basis.

`ntpraceroute.py` sends IPv6 NTP client queries to a list of NTP servers,
incrementing the IPv6 Hop Limit from `minTTL` to `maxTTL` for each server. Every
packet is sourced from a **fresh random address drawn from a /64 you control**.
That source address is the nonce: because no two (server, hop limit) pairs share
one, any later traffic arriving at that address can be attributed unambiguously
back to the single NTP query that revealed it, including which server was
queried and at what hop limit.

Probing a server stops early at the first hop limit that elicits an NTP reply —
that hop's nonce is the **endpoint nonce** (the server itself saw it). Nonces
from shorter hop limits, which expired in transit, are **on-path nonces** (only
routers along the path saw them). The distinction is recorded in the output and
is what lets the clustering stage separate endpoint observers from on-path
observers.

## Requirements

```
pip install -r requirements.txt
```

- Python 3.8+, `scapy`, `dnspython`
- Root (or `CAP_NET_RAW`) to send raw packets via Scapy
- An IPv6 /64 routed to the probing host, with inbound traffic to the whole
  prefix reaching your capture interface

## Usage

```
sudo python3 ntpraceroute.py \
  -n <IPv6-/64>     \   # source /64 you own, e.g. 2001:db8::/64
  -f <targets-file> \   # one IPv6 NTP server address per line
  -p <output-prefix>    # prefix for output JSONL filenames
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-n`, `--network` | (required) | IPv6 /64 to draw random source addresses from |
| `-f`, `--fname` | (required) | File containing IPv6 NTP server addresses, one per line |
| `-p`, `--prefix` | (required) | Prefix for output JSONL filenames |
| `-m`, `--minTTL` | `1` | Minimum hop limit to probe |
| `-x`, `--maxTTL` | `32` | Maximum hop limit to probe |
| `-t`, `--timeout` | `10` | Seconds to wait for an NTP reply per probe |

A maximum hop limit of 32 reaches over 99.7% of responsive IPv6 pool servers
while bounding the probe volume per target; see the paper's validation section.

### Example

```
sudo python3 ntpraceroute.py \
  -n 2001:db8:1:2::/64 \
  -f ntp-servers.txt \
  -p /data/probes/run1 \
  -m 1 -x 32 -t 3
```

This writes one JSONL file per invocation, named
`<prefix>-ntp-traceroute-<unix-timestamp>.jsonl`.

## Targets

`ntp-servers.txt` contains the 2,335 IPv6 NTP Pool server addresses probed in
the study, one per line. The list is derived from the publicly enumerable NTP
Pool and will drift over time as servers join and leave.

## Output format

One JSON object per line:

```json
{
  "start_time": 1775675488,
  "dst_ip": "2001:db8::1",
  "min_ttl": 1,
  "max_ttl": 32,
  "timeout": 3,
  "hops": [
    { "ttl": 5,  "src_ip": "2001:db8:1:2::abcd", "src_port": 12345, "ntp_reply": false },
    { "ttl": 6,  "src_ip": "2001:db8:1:2::ef01", "src_port": 23456, "ntp_reply": false },
    { "ttl": 7,  "src_ip": "2001:db8:1:2::2345", "src_port": 34567, "ntp_reply": true  }
  ]
}
```

- `dst_ip` — the NTP server queried
- `hops[].ttl` — the IPv6 Hop Limit that packet was sent with
- `hops[].src_ip` — the nonce address used for that (server, hop limit) pair
- `hops[].ntp_reply: true` — endpoint nonce; the NTP server replied
- `hops[].ntp_reply: false` — on-path nonce; the packet expired in transit

Source ports are randomized and forced above 2048 so probes are not mistaken
for a common service when captures are inspected by hand.

## Capturing back-scan traffic

Nonces are only useful if you record what arrives at them. Capture all inbound
IPv6 traffic to the probing prefix, ideally starting before the first probe and
running continuously:

```
tcpdump -i eth0 -w /data/backscans.pcap ip6
```

Feed that pcap and the JSONL directory to [`../clustering/`](../clustering/).

## Probing rate

The script does not rate-limit itself. In the study, probing was paced at one
NTP request per hop limit every three seconds, with each server revisited
approximately once every ten days — well below ordinary NTP client load. The NTP
Pool is volunteer-operated public infrastructure; reproduce that pacing when
running against live pool servers.
