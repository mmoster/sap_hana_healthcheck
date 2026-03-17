#!/usr/bin/env python3
"""
Discovery Runner - Führt YAML-basierte Discovery-Regeln aus

Lädt Discovery-Regeln aus YAML-Dateien und sammelt Informationen
von Remote-Hosts via SSH.
"""

import os
import sys
import yaml
import argparse
import subprocess
import re
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Tuple

# Pfad zum Wrapper-Modul hinzufügen
SCRIPT_DIR = Path(__file__).parent.resolve()
WRAPPER_DIR = SCRIPT_DIR.parent.parent / "wrapper"
sys.path.insert(0, str(WRAPPER_DIR / "access"))

from discover_access import AccessDiscovery


@dataclass
class DiscoveryResult:
    """Ergebnis einer einzelnen Discovery"""
    id: str
    description: str
    success: bool
    raw_output: str
    parsed_value: Any
    error: Optional[str] = None
    timestamp: Optional[str] = None


@dataclass
class DiscoveredData:
    """Gesammelte Discovery-Daten für einen Host"""
    hostname: str
    access_method: str
    discovery_timestamp: str
    groups: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class DiscoveryRunner:
    """Führt Discovery-Regeln aus und sammelt Ergebnisse"""

    SSH_TIMEOUT = 30
    MAX_WORKERS = 5

    def __init__(self, rules_dir: str, config_dir: str = ".", debug: bool = False):
        self.rules_dir = Path(rules_dir)
        self.config_dir = Path(config_dir)
        self.rules: Dict[str, Dict] = {}  # group -> rules
        self.results: Dict[str, DiscoveredData] = {}  # hostname -> data
        self.debug = debug

    def _debug_print(self, message: str):
        """Print debug message if debug mode is enabled."""
        if self.debug:
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            print(f"  [DEBUG {timestamp}] {message}")

    def load_rules(self) -> Dict[str, Dict]:
        """Lädt alle Discovery-Regeln aus YAML-Dateien"""
        self.rules = {}

        if not self.rules_dir.exists():
            print(f"[ERROR] Rules directory not found: {self.rules_dir}")
            return self.rules

        rule_files = sorted(self.rules_dir.glob("*.yaml"))
        print(f"\n{'='*60}")
        print(f" Loading Discovery Rules from {self.rules_dir}")
        print(f"{'='*60}")

        self._debug_print(f"Rules directory: {self.rules_dir}")
        self._debug_print(f"Config directory: {self.config_dir}")
        self._debug_print(f"Found {len(rule_files)} rule files")

        for rule_file in rule_files:
            try:
                with open(rule_file, 'r') as f:
                    data = yaml.safe_load(f)

                if not data or not data.get('enabled', True):
                    print(f"  [SKIP] {rule_file.name} (disabled)")
                    continue

                group = data.get('group', rule_file.stem)
                self.rules[group] = {
                    'description': data.get('description', ''),
                    'discoveries': data.get('discoveries', []),
                    'file': str(rule_file)
                }

                disc_count = len(data.get('discoveries', []))
                print(f"  [LOAD] {group}: {disc_count} discoveries")

            except Exception as e:
                print(f"  [ERROR] {rule_file.name}: {e}")

        total = sum(len(g['discoveries']) for g in self.rules.values())
        print(f"\nTotal: {len(self.rules)} groups, {total} discoveries")
        return self.rules

    def _execute_ssh_command(self, cmd: str, host: str,
                              user: str = None) -> Tuple[bool, str]:
        """Führt einen SSH-Befehl aus"""
        ssh_user = user or os.environ.get('USER', 'root')

        try:
            full_cmd = [
                "ssh", "-o", "BatchMode=yes",
                "-o", f"ConnectTimeout=10",
                "-o", "StrictHostKeyChecking=no",
                f"{ssh_user}@{host}",
                cmd
            ]

            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=self.SSH_TIMEOUT
            )

            return result.returncode == 0, result.stdout.strip()

        except subprocess.TimeoutExpired:
            return False, f"Timeout after {self.SSH_TIMEOUT}s"
        except Exception as e:
            return False, str(e)

    def _parse_output(self, output: str, parser_config: Dict) -> Any:
        """Parst die Ausgabe gemäß Konfiguration"""
        parser_type = parser_config.get('type', 'raw')

        if parser_type == 'raw':
            return output.strip()

        elif parser_type == 'lines':
            lines = output.strip().split('\n')
            if parser_config.get('filter_empty', False):
                lines = [l for l in lines if l.strip()]
            return lines

        elif parser_type == 'key_value':
            result = {}
            delimiter = parser_config.get('delimiter', '=')
            strip_quotes = parser_config.get('strip_quotes', False)

            for line in output.strip().split('\n'):
                if delimiter in line:
                    key, _, value = line.partition(delimiter)
                    key = key.strip()
                    value = value.strip()
                    if strip_quotes:
                        value = value.strip('"\'')
                    result[key] = value
            return result

        elif parser_type == 'regex':
            result = {}
            patterns = parser_config.get('patterns', [])

            for pattern in patterns:
                name = pattern.get('name')
                regex = pattern.get('regex')
                group = pattern.get('group', 0)

                if name and regex:
                    try:
                        match = re.search(regex, output, re.MULTILINE)
                        if match:
                            result[name] = match.group(group)
                        else:
                            result[name] = None
                    except Exception:
                        result[name] = None

            return result

        return output

    def run_discovery(self, discovery: Dict, host: str,
                      user: str = None) -> DiscoveryResult:
        """Führt eine einzelne Discovery aus"""
        disc_id = discovery.get('id', 'UNKNOWN')
        description = discovery.get('description', '')
        cmd = discovery.get('live_cmd', '')
        parser_config = discovery.get('parser', {'type': 'raw'})

        self._debug_print(f"Running {disc_id} on {host}: {cmd[:50]}...")

        if not cmd:
            return DiscoveryResult(
                id=disc_id,
                description=description,
                success=False,
                raw_output='',
                parsed_value=None,
                error='No command defined',
                timestamp=datetime.now().isoformat()
            )

        success, output = self._execute_ssh_command(cmd, host, user)

        if success:
            parsed = self._parse_output(output, parser_config)
            return DiscoveryResult(
                id=disc_id,
                description=description,
                success=True,
                raw_output=output,
                parsed_value=parsed,
                timestamp=datetime.now().isoformat()
            )
        else:
            return DiscoveryResult(
                id=disc_id,
                description=description,
                success=False,
                raw_output=output,
                parsed_value=None,
                error=output,
                timestamp=datetime.now().isoformat()
            )

    def run_group(self, group_name: str, host: str,
                  user: str = None) -> Dict[str, DiscoveryResult]:
        """Führt alle Discoveries einer Gruppe aus"""
        results = {}

        if group_name not in self.rules:
            return results

        group = self.rules[group_name]
        discoveries = group.get('discoveries', [])

        print(f"\n  [{group_name}] Running {len(discoveries)} discoveries...")

        for disc in discoveries:
            disc_id = disc.get('id', 'UNKNOWN')
            result = self.run_discovery(disc, host, user)
            results[disc_id] = result

            status = "OK" if result.success else "FAIL"
            print(f"    [{status}] {disc_id}: {result.description[:40]}")

        return results

    def run_all(self, hosts: Dict[str, Dict],
                groups: List[str] = None) -> Dict[str, DiscoveredData]:
        """Führt alle Discoveries auf allen Hosts aus"""
        self.results = {}

        groups_to_run = groups or list(self.rules.keys())

        print(f"\n{'='*60}")
        print(f" Running Discoveries")
        print(f"{'='*60}")
        print(f" Hosts: {len(hosts)}")
        print(f" Groups: {', '.join(groups_to_run)}")

        self._debug_print(f"Total hosts: {list(hosts.keys())}")
        self._debug_print(f"Groups to run: {groups_to_run}")

        for hostname, node_info in hosts.items():
            method = node_info.get('preferred_method')
            user = node_info.get('ssh_user')

            if not method or method == 'sosreport':
                print(f"\n[SKIP] {hostname}: No live access (method={method})")
                continue

            print(f"\n{'='*60}")
            print(f" Host: {hostname} (via {method})")
            print(f"{'='*60}")

            host_data = DiscoveredData(
                hostname=hostname,
                access_method=method,
                discovery_timestamp=datetime.now().isoformat()
            )

            for group_name in groups_to_run:
                group_results = self.run_group(group_name, hostname, user)

                # Ergebnisse strukturiert speichern
                host_data.groups[group_name] = {}
                for disc_id, result in group_results.items():
                    store_as = None
                    # Finde store_as aus Discovery-Definition
                    for disc in self.rules[group_name]['discoveries']:
                        if disc.get('id') == disc_id:
                            store_as = disc.get('store_as', disc_id)
                            break

                    host_data.groups[group_name][store_as or disc_id] = {
                        'success': result.success,
                        'value': result.parsed_value,
                        'raw': result.raw_output if result.success else None,
                        'error': result.error
                    }

                    if not result.success:
                        host_data.errors.append(f"{disc_id}: {result.error}")

            self.results[hostname] = host_data

        return self.results

    def save_results(self, output_file: str = None) -> str:
        """Speichert die Ergebnisse in eine YAML-Datei"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.config_dir / f"discovered_data_{timestamp}.yaml"
        else:
            output_file = Path(output_file)

        # Ergebnisse in serialisierbares Format konvertieren
        output_data = {
            'discovery_run': {
                'timestamp': datetime.now().isoformat(),
                'rules_dir': str(self.rules_dir),
                'groups': list(self.rules.keys()),
                'hosts_count': len(self.results)
            },
            'hosts': {}
        }

        for hostname, data in self.results.items():
            output_data['hosts'][hostname] = {
                'access_method': data.access_method,
                'discovery_timestamp': data.discovery_timestamp,
                'data': data.groups,
                'errors': data.errors if data.errors else None
            }

        with open(output_file, 'w') as f:
            yaml.dump(output_data, f, default_flow_style=False,
                     sort_keys=False, allow_unicode=True)

        print(f"\n[SAVED] Results written to: {output_file}")
        return str(output_file)

    def print_summary(self):
        """Gibt eine Zusammenfassung aus"""
        print(f"\n{'='*60}")
        print(f" Discovery Summary")
        print(f"{'='*60}")

        for hostname, data in self.results.items():
            total_discoveries = sum(len(g) for g in data.groups.values())
            successful = sum(
                1 for g in data.groups.values()
                for v in g.values() if v.get('success')
            )

            print(f"\n  {hostname}:")
            print(f"    Access: {data.access_method}")
            print(f"    Discoveries: {successful}/{total_discoveries} successful")

            if data.errors:
                print(f"    Errors: {len(data.errors)}")
                for err in data.errors[:3]:
                    print(f"      - {err[:60]}")
                if len(data.errors) > 3:
                    print(f"      ... and {len(data.errors) - 3} more")


def main():
    parser = argparse.ArgumentParser(
        description='Run YAML-based discovery rules on cluster hosts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              Run all discoveries
  %(prog)s --groups system_info         Run only system_info group
  %(prog)s --list-rules                 List available rules
  %(prog)s --host hana04                Run only on specific host
  %(prog)s --debug                      Run with debug output
"""
    )

    parser.add_argument(
        '--rules-dir', '-r',
        default=str(SCRIPT_DIR / 'discovery_rules'),
        help='Directory containing discovery rule YAML files'
    )
    parser.add_argument(
        '--config-dir', '-c',
        default=str(SCRIPT_DIR),
        help='Directory for access config and output files'
    )
    parser.add_argument(
        '--hosts-file', '-H',
        default=str(SCRIPT_DIR / 'hosts.txt'),
        help='File containing list of hosts'
    )
    parser.add_argument(
        '--groups', '-g',
        nargs='+',
        help='Specific groups to run (default: all)'
    )
    parser.add_argument(
        '--host',
        help='Run only on specific host'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file for results (default: auto-generated)'
    )
    parser.add_argument(
        '--list-rules', '-l',
        action='store_true',
        help='List available discovery rules and exit'
    )
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Force access rediscovery'
    )
    parser.add_argument(
        '--show-data', '-s',
        action='store_true',
        help='Show collected data at the end'
    )
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug mode (show config files used and step progress)'
    )

    args = parser.parse_args()

    # Discovery Runner initialisieren
    runner = DiscoveryRunner(
        rules_dir=args.rules_dir,
        config_dir=args.config_dir,
        debug=args.debug
    )

    # Debug banner
    if args.debug:
        print(f"\n{'='*60}")
        print(" DEBUG MODE ENABLED - Configuration Files")
        print(f"{'='*60}")
        print(f"  Rules directory:     {args.rules_dir}")
        print(f"  Config directory:    {args.config_dir}")
        print(f"  Hosts file:          {args.hosts_file}")
        print(f"  Access config:       {Path(args.config_dir) / 'cluster_access_config.yaml'}")
        print()

    # Regeln laden
    runner.load_rules()

    # Wenn nur Regeln auflisten
    if args.list_rules:
        print(f"\n{'='*60}")
        print(" Available Discovery Rules")
        print(f"{'='*60}")
        for group, data in runner.rules.items():
            print(f"\n[{group}] {data['description']}")
            for disc in data['discoveries']:
                print(f"  - {disc['id']}: {disc.get('description', '')[:50]}")
        sys.exit(0)

    # Access Discovery durchführen
    print(f"\n{'='*60}")
    print(" Step 1: Access Discovery")
    print(f"{'='*60}")

    access_discovery = AccessDiscovery(
        config_dir=args.config_dir,
        hosts_file=args.hosts_file,
        force_rediscover=args.force
    )

    access_config = access_discovery.discover_all()

    # Hosts filtern wenn gewünscht
    hosts = access_config.nodes
    if args.host:
        if args.host in hosts:
            hosts = {args.host: hosts[args.host]}
        else:
            print(f"[ERROR] Host not found: {args.host}")
            sys.exit(1)

    # Prüfen ob zugängliche Hosts vorhanden
    accessible_hosts = {
        h: info for h, info in hosts.items()
        if info.get('preferred_method') and info.get('preferred_method') != 'sosreport'
    }

    if not accessible_hosts:
        print("[ERROR] No accessible hosts found for live discovery")
        sys.exit(1)

    # Discoveries ausführen
    print(f"\n{'='*60}")
    print(" Step 2: Running Discoveries")
    print(f"{'='*60}")

    runner.run_all(accessible_hosts, groups=args.groups)

    # Zusammenfassung
    runner.print_summary()

    # Ergebnisse speichern
    output_file = runner.save_results(args.output)

    # Optional: Daten anzeigen
    if args.show_data:
        print(f"\n{'='*60}")
        print(" Collected Data")
        print(f"{'='*60}")

        with open(output_file, 'r') as f:
            print(f.read())


if __name__ == '__main__':
    main()
