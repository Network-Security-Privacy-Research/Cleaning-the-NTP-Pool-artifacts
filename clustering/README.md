# Artifact 2 — Clustering NTP scanners with their scanning infrastructure

> Scripts used to cluster IPv6 NTP server scanners with their scanning
> infrastructure.

`cluster_backscans.py` ingests the JSONL probe records from
[`../nonced-probing/`](../nonced-probing/) together with a pcap of inbound
traffic to the probing prefix, and groups NTP servers with the hosts that
scanned the nonces those servers observed.

## How the clustering works

Each nonce address was revealed to exactly one NTP server, at one hop limit.
When a scanner IP sends traffic to a nonce, that establishes an edge

```
(NTP target) —— (scanner IP)
```

in a bipartite graph. Clusters are the **connected components** of that graph:
two NTP servers land in the same cluster when they share scanning
infrastructure, and a scanner joins every cluster whose nonces it touched.
Because components merge transitively, a single third-party scanner touching
nonces from many servers pulls all of those servers into one cluster — which is
precisely the shared-infrastructure relationship being measured.

Only **endpoint nonces** (`ntp_reply: true`) participate. On-path nonces are
excluded, so clusters describe endpoint observers rather than transit
observers. A scanner IP that is also one of the NTP targets is recorded as a
*self-scanner*, and clusters are labelled `self-only`, `third-party only`, or
`mixed` accordingly.

The following traffic is filtered out before clustering:

- Link-local (`fe80::`) traffic — neighbor discovery, not scanning
- NTP replies from the probed server itself (UDP source port 123)
- ICMPv6 other than echo requests (type 128)

## Requirements

- Python 3.8+ — standard library only, no pip packages
- `tshark` (Wireshark CLI) on `$PATH`

## Usage

```
python3 cluster_backscans.py \
  --jsonl-dir <dir>  \   # directory containing *.jsonl probe files
  --pcap <file>      \   # pcap of inbound back-scan traffic
  --output <file>        # SQLite output path (default: backscans.db)
```

### Example

```
python3 cluster_backscans.py \
  --jsonl-dir /data/probes/ \
  --pcap /data/backscans.pcap \
  --output results.db
```

Progress, cluster counts, and a one-line verdict per cluster are printed to
stdout as it runs.

### Output database schema

| Table | Description |
|-------|-------------|
| `nonces` | All endpoint nonce IPs with their NTP target, hop limit, and probe time |
| `backscans` | Every inbound packet to an endpoint nonce: timestamp, scanner IP, protocol, ports, TCP flags |
| `clusters` | One row per cluster: target/scanner counts, member lists, verdict string |
| `cluster_members` | Maps each NTP target to its cluster ID |
| `cluster_scanners` | Maps each scanner IP to its cluster ID |
| `cluster_edges` | Per (NTP target, scanner IP) pair: packet count, protocols, TCP/UDP destination ports |

### Cluster verdict strings

| Verdict | Meaning |
|---------|---------|
| `self-only: N targets scanning themselves` | Every scanner IP is also an NTP target — the servers scan their own nonces |
| `third-party only: N scanners across M targets` | No NTP target scans its own nonces; all scanning comes from distinct infrastructure |
| `mixed: N self-scans + M shared third-party scanners across K targets` | Both self-scanning and third-party scanning, connected by shared scanner infrastructure |

### Querying the output

```sql
-- Clusters with the most NTP targets
SELECT cluster_id, n_targets, n_scanners, verdict
FROM clusters ORDER BY n_targets DESC;

-- All scanner IPs in cluster 0
SELECT scanner_ip FROM cluster_scanners WHERE cluster_id = 0;

-- Ports scanned by cluster 0
SELECT ntp_target, scanner_ip, tcp_dports
FROM cluster_edges
WHERE ntp_target IN (SELECT ntp_target FROM cluster_members WHERE cluster_id = 0);

-- Delay between the probe that revealed a nonce and the first scan of it
SELECT b.scanner_ip, MIN(b.ts) - n.probe_time AS delay_seconds
FROM backscans b JOIN nonces n USING (nonce_ip)
GROUP BY b.nonce_ip, b.scanner_ip;
```

## Input data

The pcap and JSONL inputs from the study are not released — see the scope note
in [`../README.md`](../README.md). Reproducing these results requires running
[`../nonced-probing/`](../nonced-probing/) to generate your own.
