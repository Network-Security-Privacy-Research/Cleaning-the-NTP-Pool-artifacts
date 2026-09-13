#!/usr/bin/env python3
"""
cluster_backscans.py — cluster NTP servers with their back-scanning infrastructure.

Inputs:
  --jsonl-dir DIR   directory of *.jsonl NTP traceroute probe files
  --pcap FILE       pcap of inbound backscan traffic captured at the probe host
  --output FILE     SQLite output path (default: backscans.db)

Only endpoint nonces (hops where ntp_reply=True in JSONL) are considered.
On-path nonces (intermediate hops) are ignored.
Link-local (fe80::) traffic and NTP self-replies are filtered out.

Clustering: connected components of the bipartite graph
  (NTP target) -- (scanner IP)
where an edge exists if a scanner IP sent packets to a nonce
that was reached by that NTP target.

Output schema mirrors filtered_backscans.db.
"""

import argparse
import glob
import json
import os
import sqlite3
import subprocess
import sys
from collections import defaultdict


# ── Union-Find for connected components ──────────────────────────────────────

class UnionFind:
    def __init__(self):
        self._parent = {}

    def find(self, x):
        self._parent.setdefault(x, x)
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def union(self, a, b):
        self._parent.setdefault(a, a)
        self._parent.setdefault(b, b)
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[ra] = rb

    def groups(self):
        result = defaultdict(set)
        for x in self._parent:
            result[self.find(x)].add(x)
        return dict(result)


# ── JSONL parsing ─────────────────────────────────────────────────────────────

def load_nonces(jsonl_dir):
    """
    Returns:
      endpoint_nonces: dict  nonce_ip -> {ntp_target, probe_time, ttl}
      onpath_nonces:   set   nonce IPs that are intermediate hops only
    """
    endpoint = {}   # nonce_ip -> {ntp_target, probe_time, ttl}
    onpath   = set()

    pattern = os.path.join(jsonl_dir, '*.jsonl')
    files = sorted(glob.glob(pattern))
    if not files:
        sys.exit(f'No .jsonl files found in {jsonl_dir}')

    print(f'  Loading {len(files)} JSONL files from {jsonl_dir}')
    for fp in files:
        with open(fp) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f'  Warning: bad JSON in {fp}: {e}', file=sys.stderr)
                    continue

                ntp_target = d.get('dst_ip')
                probe_time = float(d.get('start_time', 0))

                for hop in d.get('hops', []):
                    nonce_ip = hop.get('src_ip')
                    if not nonce_ip:
                        continue
                    ttl = hop.get('ttl', 0)
                    if hop.get('ntp_reply') is True:
                        # Endpoint nonce: the NTP server replied
                        endpoint[nonce_ip] = {
                            'ntp_target': ntp_target,
                            'probe_time': probe_time,
                            'ttl': ttl,
                        }
                    else:
                        # On-path (intermediate) nonce — ignored for clustering
                        onpath.add(nonce_ip)

    # A nonce may appear as both on-path (for one probe) and endpoint (for
    # another). Endpoint classification takes precedence.
    onpath -= set(endpoint.keys())

    print(f'  {len(endpoint):,} endpoint nonces ({len(set(v["ntp_target"] for v in endpoint.values())):,} NTP targets)')
    print(f'  {len(onpath):,} on-path nonces (ignored)')
    return endpoint


# ── pcap parsing ──────────────────────────────────────────────────────────────

def parse_pcap(pcap_path, endpoint_nonces):
    """
    Parse pcap with tshark. Returns list of dicts:
      {scanner_ip, nonce_ip, ts, proto, sport, dport, tcp_flags}

    Filtered to:
      - dst in endpoint_nonces
      - not fe80:: (link-local / NDP)
      - not the NTP target itself (self-reply filter applied later per nonce)
    """
    print(f'  Parsing {pcap_path} with tshark...')
    nonce_set = set(endpoint_nonces.keys())

    cmd = [
        'tshark', '-r', pcap_path, '-T', 'fields', '-E', 'separator=\t',
        '-e', 'frame.time_epoch',
        '-e', 'ipv6.src',
        '-e', 'ipv6.dst',
        '-e', 'ipv6.nxt',
        '-e', 'tcp.srcport',
        '-e', 'tcp.dstport',
        '-e', 'tcp.flags',
        'ipv6 and not (udp.srcport == 123) and not (icmpv6 and icmpv6.type != 128)',
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f'tshark failed: {result.stderr[:500]}')

    packets = []
    skipped_onpath = 0
    skipped_linklocal = 0
    for line in result.stdout.splitlines():
        parts = line.split('\t')
        if len(parts) < 3:
            continue
        ts_str, src, dst = parts[0], parts[1], parts[2]
        if not src or not dst:
            continue

        # Strip any comma-separated duplicates tshark may emit
        src = src.split(',')[0].strip()
        dst = dst.split(',')[0].strip()

        if dst not in nonce_set:
            skipped_onpath += 1
            continue
        if src.lower().startswith('fe80:'):
            skipped_linklocal += 1
            continue

        proto_num = parts[3].split(',')[0].strip() if len(parts) > 3 else ''
        proto_map = {'6': 'TCP', '17': 'UDP', '58': 'ICMPv6'}
        proto = proto_map.get(proto_num, proto_num or 'other')

        sport     = int(parts[4]) if len(parts) > 4 and parts[4].strip().isdigit() else None
        dport     = int(parts[5]) if len(parts) > 5 and parts[5].strip().isdigit() else None
        tcp_flags = parts[6].strip() if len(parts) > 6 else None

        try:
            ts = float(ts_str)
        except ValueError:
            continue

        packets.append({
            'ts':         ts,
            'scanner_ip': src,
            'nonce_ip':   dst,
            'proto':      proto,
            'sport':      sport,
            'dport':      dport,
            'tcp_flags':  tcp_flags,
        })

    print(f'  {len(packets):,} packets to endpoint nonces'
          f' ({skipped_linklocal:,} link-local dropped, '
          f'{skipped_onpath:,} on-path/unknown dropped)')
    return packets


# ── clustering ────────────────────────────────────────────────────────────────

def build_clusters(packets, endpoint_nonces):
    """
    Build connected components of the bipartite graph (NTP target, scanner_ip).
    Self-scans (scanner == ntp_target) are included in the graph so they form
    their own cluster or merge with related third-party scanners.

    Returns list of dicts:
      {targets: set, scanners: set, self_scanners: set, edges: list}
    """
    uf = UnionFind()
    # edges: (ntp_target, scanner_ip, packets, protocols, tcp_dports, udp_dports)
    edge_data = defaultdict(lambda: {'packets': 0, 'protos': set(),
                                     'tcp_dports': set(), 'udp_dports': set()})

    for pkt in packets:
        info = endpoint_nonces[pkt['nonce_ip']]
        ntp_target  = info['ntp_target']
        scanner_ip  = pkt['scanner_ip']

        # Tag nodes so NTP target and scanner IPs with same address don't collide
        t_node = ('T', ntp_target)
        s_node = ('S', scanner_ip)
        uf.union(t_node, s_node)

        key = (ntp_target, scanner_ip)
        edge_data[key]['packets'] += 1
        edge_data[key]['protos'].add(pkt['proto'])
        if pkt['proto'] == 'TCP' and pkt['dport'] is not None:
            edge_data[key]['tcp_dports'].add(pkt['dport'])
        elif pkt['proto'] == 'UDP' and pkt['dport'] is not None:
            edge_data[key]['udp_dports'].add(pkt['dport'])

    # Reconstruct clusters from union-find groups
    all_targets  = {('T', v['ntp_target']) for v in endpoint_nonces.values()}
    all_scanners = {('S', pkt['scanner_ip']) for pkt in packets}

    groups = uf.groups()
    clusters = []
    for root, members in groups.items():
        targets  = {ip for tag, ip in members if tag == 'T'}
        scanners = {ip for tag, ip in members if tag == 'S'}
        if not targets or not scanners:
            continue
        self_scanners = targets & scanners
        clusters.append({
            'targets':       targets,
            'scanners':      scanners,
            'self_scanners': self_scanners,
        })

    clusters.sort(key=lambda c: (-len(c['targets']), -len(c['scanners'])))
    return clusters, edge_data


def describe_cluster(c):
    n_t    = len(c['targets'])
    n_s    = len(c['scanners'])
    n_self = len(c['self_scanners'])
    n_3p   = n_s - n_self

    if n_self == n_s:
        return f'self-only: {n_t} target{"s" if n_t>1 else ""} scanning themselves'
    if n_self == 0:
        if n_s == 1 and n_t == 1:
            scanner = next(iter(c['scanners']))
            return f'single target, single third-party scanner: {scanner}'
        return f'third-party only: {n_s} scanners across {n_t} target{"s" if n_t>1 else ""}'
    return (f'mixed: {n_self} self-scan{"s" if n_self>1 else ""} + '
            f'{n_3p} shared third-party scanner{"s" if n_3p>1 else ""} '
            f'across {n_t} targets')


# ── SQLite output ─────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS nonces (
    nonce_ip          TEXT PRIMARY KEY,
    ntp_target        TEXT NOT NULL,
    ttl               INTEGER,
    probe_time        REAL
);
CREATE TABLE IF NOT EXISTS backscans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    nonce_ip    TEXT NOT NULL,
    ts          REAL NOT NULL,
    scanner_ip  TEXT NOT NULL,
    proto       TEXT,
    sport       INTEGER,
    dport       INTEGER,
    tcp_flags   TEXT,
    FOREIGN KEY (nonce_ip) REFERENCES nonces(nonce_ip)
);
CREATE TABLE IF NOT EXISTS clusters (
    cluster_id              INTEGER PRIMARY KEY,
    n_targets               INTEGER,
    n_scanners              INTEGER,
    n_self_scanners         INTEGER,
    n_third_party_scanners  INTEGER,
    targets                 TEXT,
    scanners                TEXT,
    verdict                 TEXT
);
CREATE TABLE IF NOT EXISTS cluster_members (
    ntp_target  TEXT NOT NULL,
    cluster_id  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cluster_scanners (
    scanner_ip  TEXT NOT NULL,
    cluster_id  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cluster_edges (
    ntp_target  TEXT NOT NULL,
    scanner_ip  TEXT NOT NULL,
    packets     INTEGER,
    protocols   TEXT,
    tcp_dports  TEXT,
    udp_dports  TEXT
);
CREATE INDEX IF NOT EXISTS idx_backscans_nonce   ON backscans(nonce_ip);
CREATE INDEX IF NOT EXISTS idx_backscans_scanner ON backscans(scanner_ip);
CREATE INDEX IF NOT EXISTS idx_backscans_ts      ON backscans(ts);
CREATE INDEX IF NOT EXISTS idx_cm_target         ON cluster_members(ntp_target);
CREATE INDEX IF NOT EXISTS idx_cm_cluster        ON cluster_members(cluster_id);
CREATE INDEX IF NOT EXISTS idx_cs_scanner        ON cluster_scanners(scanner_ip);
CREATE INDEX IF NOT EXISTS idx_cs_cluster        ON cluster_scanners(cluster_id);
"""


def write_db(db_path, endpoint_nonces, packets, clusters, edge_data):
    if os.path.exists(db_path):
        os.remove(db_path)
    con = sqlite3.connect(db_path)
    con.executescript(SCHEMA)

    # nonces
    con.executemany(
        'INSERT OR IGNORE INTO nonces VALUES (?,?,?,?)',
        [(ip, v['ntp_target'], v['ttl'], v['probe_time'])
         for ip, v in endpoint_nonces.items()]
    )

    # backscans — only packets to nonces that ended up in a cluster
    clustered_nonces = set(endpoint_nonces.keys())
    con.executemany(
        'INSERT INTO backscans (nonce_ip,ts,scanner_ip,proto,sport,dport,tcp_flags) '
        'VALUES (?,?,?,?,?,?,?)',
        [(p['nonce_ip'], p['ts'], p['scanner_ip'], p['proto'],
          p['sport'], p['dport'], p['tcp_flags'])
         for p in packets if p['nonce_ip'] in clustered_nonces]
    )

    # clusters, cluster_members, cluster_scanners, cluster_edges
    for cid, c in enumerate(clusters):
        n_self = len(c['self_scanners'])
        n_3p   = len(c['scanners']) - n_self
        con.execute(
            'INSERT INTO clusters VALUES (?,?,?,?,?,?,?,?)',
            (cid, len(c['targets']), len(c['scanners']),
             n_self, n_3p,
             ','.join(sorted(c['targets'])),
             ','.join(sorted(c['scanners'])),
             describe_cluster(c))
        )
        con.executemany('INSERT INTO cluster_members VALUES (?,?)',
                        [(t, cid) for t in c['targets']])
        con.executemany('INSERT INTO cluster_scanners VALUES (?,?)',
                        [(s, cid) for s in c['scanners']])

    con.executemany(
        'INSERT INTO cluster_edges VALUES (?,?,?,?,?,?)',
        [(ntp, scanner,
          ed['packets'],
          ','.join(sorted(ed['protos'])),
          ','.join(str(p) for p in sorted(ed['tcp_dports'])),
          ','.join(str(p) for p in sorted(ed['udp_dports'])))
         for (ntp, scanner), ed in edge_data.items()]
    )

    con.commit()
    con.close()


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='Cluster NTP back-scanners from JSONL probes + pcap.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('--jsonl-dir', required=True,
                    help='Directory containing *.jsonl NTP traceroute files')
    ap.add_argument('--pcap', required=True,
                    help='pcap file of inbound backscan traffic')
    ap.add_argument('--output', default='backscans.db',
                    help='SQLite output file (default: backscans.db)')
    args = ap.parse_args()

    print('Loading nonces from JSONL...')
    endpoint_nonces = load_nonces(args.jsonl_dir)

    print('Parsing pcap...')
    packets = parse_pcap(args.pcap, endpoint_nonces)

    if not packets:
        print('No packets matched endpoint nonces. Check pcap and JSONL alignment.')
        sys.exit(1)

    print('Building clusters...')
    clusters, edge_data = build_clusters(packets, endpoint_nonces)

    total_targets  = sum(len(c['targets'])  for c in clusters)
    total_scanners = sum(len(c['scanners']) for c in clusters)
    print(f'  {len(clusters)} clusters, '
          f'{total_targets} NTP targets, '
          f'{total_scanners} scanner IPs')
    for cid, c in enumerate(clusters):
        print(f'  Cluster {cid}: {len(c["targets"])} targets, '
              f'{len(c["scanners"])} scanners — {describe_cluster(c)}')

    print(f'Writing {args.output}...')
    write_db(args.output, endpoint_nonces, packets, clusters, edge_data)
    print(f'Done: {args.output}')


if __name__ == '__main__':
    main()
