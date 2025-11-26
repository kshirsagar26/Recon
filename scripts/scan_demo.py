import asyncio
import json
import sys
import traceback
import argparse
import asyncio
import json
import sys
import traceback
from dataclasses import asdict
import os
import socket

# Add repository root to sys.path so imports work from any CWD
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, repo_root)

try:
    from backend.app.modules.port_scan.engine import PortScanner
except Exception as e:
    print('IMPORT_ERROR:', str(e))
    raise


def parse_ports(ports_str: str):
    """Parse a ports string like '22,80,1000-1010' into a list of ints."""
    if not ports_str:
        return None
    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            try:
                a_i = int(a); b_i = int(b)
            except ValueError:
                continue
            ports.update(range(min(a_i, b_i), max(a_i, b_i) + 1))
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return sorted(ports)


async def run_scan(args):
    scanner = PortScanner(timeout=args.timeout, max_workers=args.max_workers)

    # Resolve target
    try:
        ip = socket.gethostbyname(args.target)
    except Exception:
        ip = args.target

    # If user wants common ports
    if args.common:
        results, metrics = await scanner.scan_common_ports(args.target)
    else:
        ports = parse_ports(args.ports) if args.ports else None
        if ports:
            start_port = min(ports)
            end_port = max(ports)
        else:
            start_port = 1
            end_port = 1024

        results, metrics = await scanner.scan_port_range(
            ip,
            start_port=start_port,
            end_port=end_port,
            use_common_ports=False,
            technique=args.technique
        )

        # If ports were specified, filter results to those ports
        if ports:
            results = [r for r in results if r.port in ports]

    out = {
        'target': args.target,
        'results': [asdict(r) for r in results],
        'metrics': asdict(metrics)
    }

    text = json.dumps(out, indent=2, default=str)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f'Wrote results to {args.output}')
    else:
        print(text)


def main():
    parser = argparse.ArgumentParser(description='Demo port scanner runner')
    parser.add_argument('--target', '-t', required=True, help='Target hostname or IP')
    parser.add_argument('--ports', '-p', help="Comma-separated ports and ranges, e.g. '22,80,1000-1010'")
    parser.add_argument('--technique', choices=['tcp_connect', 'syn', 'udp', 'hybrid'], default='tcp_connect')
    parser.add_argument('--timeout', type=float, default=3.0)
    parser.add_argument('--max-workers', type=int, default=50)
    parser.add_argument('--output', '-o', help='Output JSON file path')
    parser.add_argument('--common', action='store_true', help='Scan common ports only')

    args = parser.parse_args()

    try:
        asyncio.run(run_scan(args))
    except Exception:
        traceback.print_exc()


if __name__ == '__main__':
    main()
