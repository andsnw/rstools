#!/usr/bin/env python3
import argparse
import csv
import re
import sys
from collections import defaultdict

def split_line(line):
    line = line.rstrip('\n')
    pattern = r'(\d+\.\d+\.\d+\.\d+)\s*(\[[^\]]+\])'
    matches = list(re.finditer(pattern, line))

    if len(matches) <= 1:
        return [line]

    results = []
    for i, match in enumerate(matches):
        ip = match.group(1)
        community = match.group(2)
        if i < len(matches) - 1:
            results.append(f"{ip} {community}")
        else:
            description = line[match.end():].strip()
            if description:
                results.append(f"{ip} {community} {description}")
            else:
                results.append(f"{ip} {community}")

    return results

def parse_entry(line):
    line = line.strip()
    m = re.match(r'(\d+\.\d+\.\d+\.\d+)\s*(\[[^\]]+\])\s*(.*)', line)
    if m:
        return m.group(1), m.group(2), m.group(3).strip()
    return None

def write_summary(entries, summary_file):
    # Build ip -> set of communities, and ip -> best description
    ip_communities = defaultdict(set)
    ip_description = {}
    for ip, community, description in entries:
        ip_communities[ip].add(community)
        if description and ip not in ip_description:
            ip_description[ip] = description

    any_ips = {ip for ip, comms in ip_communities.items() if len(comms) > 3}

    # Build community -> ordered unique IPs, skipping any_ips
    community_ips = defaultdict(dict)  # community -> {ip: description}
    for ip, community, description in entries:
        if ip in any_ips:
            continue
        if ip not in community_ips[community]:
            community_ips[community][ip] = ip_description.get(ip, '')

    # Collect <any> IPs (deduplicated, preserving first-seen order)
    seen = set()
    for ip, community, _ in entries:
        if ip in any_ips and ip not in seen:
            seen.add(ip)
            community_ips['<any>'][ip] = ip_description.get(ip, '')

    with open(summary_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['community', 'ip', 'description'])
        for community in sorted(community_ips.keys()):
            for ip in sorted(community_ips[community].keys()):
                writer.writerow([community, ip, community_ips[community][ip]])

def main():
    """
     onesixtyone has a bug that causes it to not print a newline if a device responds with SNMP error
      'no such name'. This script will parse onesixtyone output to restore newlines.

     Also includes a feature to parse output into a CSV file for reporting.
    """
    parser = argparse.ArgumentParser(description='Split concatenated SNMP scan lines into one entry per line.')
    parser.add_argument('-i', '--input', default='snmp.txt', help='input file (default: snmp.txt)')
    parser.add_argument('-o', '--output', help='output file (default: stdout)')
    parser.add_argument('-s', '--summary', help='summary CSV file grouped by community string')
    args = parser.parse_args()

    split_lines = []
    out = open(args.output, 'w') if args.output else sys.stdout
    try:
        with open(args.input, 'r') as f:
            for line in f:
                for result in split_line(line):
                    print(result, file=out)
                    split_lines.append(result)
    finally:
        if args.output:
            out.close()

    if args.summary:
        entries = [e for e in (parse_entry(l) for l in split_lines) if e]
        write_summary(entries, args.summary)

if __name__ == '__main__':
    main()
