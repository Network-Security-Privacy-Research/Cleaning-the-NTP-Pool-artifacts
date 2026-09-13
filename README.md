# Cleaning the NTP Pool — Artifacts

Research artifacts for the CCS 2026 paper *"Cleaning the NTP Pool: Detecting and
Mitigating NTP-Sourced IPv6 Scanning."*

This repository contains the two artifacts enumerated in the paper's Open
Science appendix:

| # | Artifact | Directory |
|---|----------|-----------|
| 1 | The code necessary to generate nonced IPv6 NTP queries on a per IPv6 Hop Limit and NTP server combination basis | [`nonced-probing/`](nonced-probing/) |
| 2 | Scripts used to cluster IPv6 NTP server scanners with their scanning infrastructure | [`clustering/`](clustering/) |

## Layout

```
.
├── nonced-probing/
│   ├── ntpraceroute.py       nonced IPv6 NTP prober (artifact 1)
│   ├── ntp-servers.txt       the 2,335 IPv6 NTP Pool servers targeted
│   └── requirements.txt
└── clustering/
    ├── cluster_backscans.py  JSONL + pcap → clustered SQLite (artifact 2)
    └── requirements.txt
```

## End-to-end workflow

The two artifacts compose into a single pipeline. Probing emits JSONL recording
which nonce address was used for each (NTP server, hop limit) pair; a packet
capture on the probing prefix records who later scanned those addresses; the
clustering stage joins the two.

```bash
# 1. Capture all inbound IPv6 traffic to the probing /64 (run for the whole study)
tcpdump -i eth0 -w /data/backscans.pcap ip6

# 2. Probe the NTP servers with nonced queries, one nonce per (server, hop limit)
sudo python3 nonced-probing/ntpraceroute.py \
  -n 2001:db8:1:2::/64 \
  -f nonced-probing/ntp-servers.txt \
  -p /data/probes/run1 \
  -m 1 -x 32 -t 3

# 3. Cluster NTP servers with the infrastructure that scanned their nonces
python3 clustering/cluster_backscans.py \
  --jsonl-dir /data/probes/ \
  --pcap /data/backscans.pcap \
  --output results.db

# 4. Inspect
sqlite3 results.db "SELECT cluster_id, n_targets, n_scanners, verdict FROM clusters;"
```

See each subdirectory's `README.md` for full option documentation, output
formats, and the database schema.

## Requirements

- Python 3.8+
- `scapy` and `dnspython` for the prober (`pip install -r nonced-probing/requirements.txt`)
- Root or `CAP_NET_RAW` to send raw packets
- An IPv6 /64 you control, routed to the probing host
- `tshark` (Wireshark CLI) on `$PATH` for clustering

`cluster_backscans.py` uses only the Python standard library.

## Scope and what is not included

Consistent with the paper's Open Science and Ethical Considerations sections:

- **Raw scan data is not released.** The packet captures of inbound back-scan
  traffic, the JSONL probe records, and the resulting `backscans.db` are not
  published, given the sensitivity of the detection infrastructure and the
  ephemeral nature of IPv6 addresses. Back-scanner addresses in the paper are
  aggregated to the ASN level.
- **The target list is included.** `nonced-probing/ntp-servers.txt` is the set
  of IPv6 NTP Pool servers probed, derived from the publicly enumerable pool.
- **Rate limiting is the operator's responsibility.** The probing rate used in
  the study — one NTP request per hop limit every three seconds, with each
  server revisited roughly every ten days — is a deployment choice, not a
  default enforced by `ntpraceroute.py`. Anyone rerunning these tools against
  live NTP Pool servers should reproduce that pacing. The NTP Pool is
  volunteer-operated public infrastructure.

## Note on the stateless nonce construction

The paper's appendix describes a *stateless* nonce construction that the
monitoring system adopted after the data in this paper was collected: the nonce
is `E_k(ts | ttl | sid)`, a single DES block over a 5-byte timestamp, 1-byte
hop limit, and 2-byte server identifier, which lets an inbound packet's
destination address be decoded directly rather than looked up in a database.

The prober released here implements the scheme actually used to collect the
paper's data: a fresh random source address per (server, hop limit) pair, with
the mapping recorded in the JSONL output. `clustering/` consumes that JSONL.

## License

MIT — see [LICENSE](LICENSE).
