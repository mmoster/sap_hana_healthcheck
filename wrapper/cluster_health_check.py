#!/usr/bin/env python3
"""
SAP Pacemaker Cluster Health Check - Main Wrapper

This is the main entry point for the cluster health check tool.
It orchestrates all checks starting with access discovery.

Workflow:
1. Discover access methods to cluster nodes
2. Run cluster configuration checks (CHK_* rules)
3. Run Pacemaker/Corosync checks
4. Run SAP-specific checks
5. Generate report
"""

import os
import sys
import argparse
import yaml
from pathlib import Path
from datetime import datetime

try:
    from dataclasses import asdict
except ImportError:
    # Python < 3.7 fallback
    def asdict(obj):
        """Simple fallback for dataclasses.asdict"""
        if hasattr(obj, '__dict__'):
            return {k: v for k, v in obj.__dict__.items() if not k.startswith('_')}
        return obj

# Add modules to path
SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR / "access"))
sys.path.insert(0, str(SCRIPT_DIR / "rules"))

from discover_access import AccessDiscovery, show_config, delete_config
from engine import RulesEngine, CheckStatus, Severity


class ClusterHealthCheck:
    """Main orchestrator for SAP Pacemaker cluster health checks."""

    # Default rules path relative to script directory
    DEFAULT_RULES_PATH = str(SCRIPT_DIR / "rules" / "health_checks")

    def __init__(self, config_dir: str = None, sosreport_dir: str = None,
                 hosts_file: str = None, workers: int = 10, rules_path: str = None,
                 debug: bool = False, ansible_group: str = None, skip_ansible: bool = False):
        self.config_dir = Path(config_dir) if config_dir else SCRIPT_DIR
        self.sosreport_dir = sosreport_dir
        self.hosts_file = hosts_file
        self.workers = workers
        self.rules_path = rules_path or self.DEFAULT_RULES_PATH
        self.access_config = None
        self.rules_engine = None
        self.check_results = []
        self.debug = debug
        self.ansible_group = ansible_group
        self.skip_ansible = skip_ansible

    def _debug_print(self, message: str):
        """Print debug message if debug mode is enabled."""
        if self.debug:
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            print(f"  [DEBUG {timestamp}] {message}")

    def print_banner(self):
        """Print the tool banner."""
        print("""
╔═══════════════════════════════════════════════════════════════╗
║       SAP Pacemaker Cluster Health Check Tool                 ║
║       RHEL / SUSE Linux Enterprise                            ║
╚═══════════════════════════════════════════════════════════════╝
""")
        if self.debug:
            print("=" * 63)
            print(" DEBUG MODE ENABLED - Configuration Files")
            print("=" * 63)
            print(f"  Config directory:    {self.config_dir}")
            print(f"  Access config file:  {self.config_dir / AccessDiscovery.CONFIG_FILE}")
            print(f"  Rules path:          {self.rules_path}")
            print(f"  Hosts file:          {self.hosts_file or '(auto-discover from Ansible)'}")
            print(f"  SOSreport dir:       {self.sosreport_dir or '(not set)'}")
            print(f"  Workers:             {self.workers}")
            print()

    def step_access_discovery(self, force: bool = False) -> bool:
        """
        Step 1: Discover and validate access to cluster nodes.
        Returns True if at least one node is accessible.
        """
        print("\n" + "=" * 63)
        print(" STEP 1: Access Discovery")
        print("=" * 63)

        self._debug_print("Starting access discovery...")
        self._debug_print(f"Config file: {self.config_dir / AccessDiscovery.CONFIG_FILE}")
        self._debug_print(f"Force rediscover: {force}")

        discovery = AccessDiscovery(
            config_dir=str(self.config_dir),
            sosreport_dir=self.sosreport_dir,
            hosts_file=self.hosts_file,
            force_rediscover=force,
            debug=self.debug,
            ansible_group=self.ansible_group,
            skip_ansible=self.skip_ansible
        )
        discovery.MAX_WORKERS = self.workers

        self._debug_print(f"Hosts file: {self.hosts_file or 'auto-discover'}")
        self._debug_print(f"SOSreport dir: {self.sosreport_dir or 'not set'}")

        self.access_config = discovery.discover_all()

        self._debug_print(f"Discovery complete, found {len(self.access_config.nodes)} node(s)")

        # Check if we have any accessible nodes
        accessible_nodes = [
            node for node in self.access_config.nodes.values()
            if node.get('preferred_method')
        ]

        if not accessible_nodes:
            print("\n[ERROR] No accessible nodes found!")
            print("Please ensure at least one of the following:")
            print("  - SSH access to cluster nodes")
            print("  - Valid Ansible inventory with reachable hosts")
            print("  - SOSreport directory with extracted reports")
            return False

        print(f"\n[OK] {len(accessible_nodes)} node(s) accessible for health checks")
        return True

    def _load_rules_engine(self):
        """Initialize and load the rules engine."""
        if self.rules_engine is None:
            self._debug_print(f"Loading rules engine from: {self.rules_path}")
            access_dict = asdict(self.access_config) if self.access_config else {}
            self.rules_engine = RulesEngine(
                rules_path=self.rules_path,
                access_config=access_dict
            )
            self.rules_engine.load_rules()
            self._debug_print(f"Loaded {len(self.rules_engine.rules)} rules")

    def _filter_rules_by_prefix(self, prefixes: list) -> list:
        """Filter loaded rules by check_id prefix."""
        return [r for r in self.rules_engine.rules
                if any(r.check_id.startswith(p) for p in prefixes)]

    def step_cluster_config_check(self) -> bool:
        """
        Step 2: Check cluster configuration.
        Runs: CHK_NODE_STATUS, CHK_CLUSTER_QUORUM, CHK_QUORUM_CONFIG,
              CHK_CLONE_CONFIG, CHK_SETUP_VALIDATION
        """
        print("\n" + "=" * 63)
        print(" STEP 2: Cluster Configuration Check")
        print("=" * 63)

        self._debug_print("Starting cluster configuration checks...")
        self._load_rules_engine()

        # Filter relevant checks
        config_checks = ['CHK_NODE_STATUS', 'CHK_CLUSTER_QUORUM', 'CHK_QUORUM_CONFIG',
                        'CHK_CLONE_CONFIG', 'CHK_SETUP_VALIDATION', 'CHK_CIB_TIME_SYNC',
                        'CHK_PACKAGE_CONSISTENCY']

        rules_to_run = [r for r in self.rules_engine.rules if r.check_id in config_checks]

        self._debug_print(f"Checks to run: {[r.check_id for r in rules_to_run]}")

        if not rules_to_run:
            print("[SKIP] No cluster configuration checks found")
            return True

        nodes = self.access_config.nodes if self.access_config else {}
        self._debug_print(f"Target nodes: {list(nodes.keys())}")
        print(f"Running {len(rules_to_run)} cluster configuration checks...")

        for rule in rules_to_run:
            self._debug_print(f"Executing: {rule.check_id}")
            results = self.rules_engine.run_check(rule, nodes)
            self.check_results.extend(results)
            self._debug_print(f"Completed: {rule.check_id} ({len(results)} results)")

        failed = [r for r in self.check_results if r.status == CheckStatus.FAILED
                  and r.check_id in config_checks]
        return len([f for f in failed if f.severity == Severity.CRITICAL]) == 0

    def step_pacemaker_check(self) -> bool:
        """
        Step 3: Check Pacemaker/Corosync status.
        Runs: CHK_STONITH_CONFIG, CHK_RESOURCE_STATUS, CHK_RESOURCE_FAILURES,
              CHK_ALERT_FENCING, CHK_MASTER_SLAVE_ROLES
        """
        print("\n" + "=" * 63)
        print(" STEP 3: Pacemaker/Corosync Check")
        print("=" * 63)

        self._debug_print("Starting Pacemaker/Corosync checks...")
        self._load_rules_engine()

        pacemaker_checks = ['CHK_STONITH_CONFIG', 'CHK_RESOURCE_STATUS', 'CHK_RESOURCE_FAILURES',
                           'CHK_ALERT_FENCING', 'CHK_MASTER_SLAVE_ROLES', 'CHK_MAJORITY_MAKER']

        rules_to_run = [r for r in self.rules_engine.rules if r.check_id in pacemaker_checks]

        self._debug_print(f"Checks to run: {[r.check_id for r in rules_to_run]}")

        if not rules_to_run:
            print("[SKIP] No Pacemaker checks found")
            return True

        nodes = self.access_config.nodes if self.access_config else {}
        self._debug_print(f"Target nodes: {list(nodes.keys())}")
        print(f"Running {len(rules_to_run)} Pacemaker/Corosync checks...")

        for rule in rules_to_run:
            self._debug_print(f"Executing: {rule.check_id}")
            results = self.rules_engine.run_check(rule, nodes)
            self.check_results.extend(results)
            self._debug_print(f"Completed: {rule.check_id} ({len(results)} results)")

        failed = [r for r in self.check_results if r.status == CheckStatus.FAILED
                  and r.check_id in pacemaker_checks]
        return len([f for f in failed if f.severity == Severity.CRITICAL]) == 0

    def step_sap_check(self) -> bool:
        """
        Step 4: SAP-specific checks.
        Runs: CHK_HANA_SR_STATUS, CHK_REPLICATION_MODE, CHK_HADR_HOOKS,
              CHK_HANA_AUTOSTART, CHK_SYSTEMD_SAP, CHK_SITE_ROLES
        """
        print("\n" + "=" * 63)
        print(" STEP 4: SAP-Specific Checks")
        print("=" * 63)

        self._debug_print("Starting SAP-specific checks...")
        self._load_rules_engine()

        sap_checks = ['CHK_HANA_SR_STATUS', 'CHK_REPLICATION_MODE', 'CHK_HADR_HOOKS',
                     'CHK_HANA_AUTOSTART', 'CHK_SYSTEMD_SAP', 'CHK_SITE_ROLES']

        rules_to_run = [r for r in self.rules_engine.rules if r.check_id in sap_checks]

        self._debug_print(f"Checks to run: {[r.check_id for r in rules_to_run]}")

        if not rules_to_run:
            print("[SKIP] No SAP checks found")
            return True

        nodes = self.access_config.nodes if self.access_config else {}
        self._debug_print(f"Target nodes: {list(nodes.keys())}")
        print(f"Running {len(rules_to_run)} SAP-specific checks...")

        for rule in rules_to_run:
            self._debug_print(f"Executing: {rule.check_id}")
            results = self.rules_engine.run_check(rule, nodes)
            self.check_results.extend(results)
            self._debug_print(f"Completed: {rule.check_id} ({len(results)} results)")

        failed = [r for r in self.check_results if r.status == CheckStatus.FAILED
                  and r.check_id in sap_checks]
        return len([f for f in failed if f.severity == Severity.CRITICAL]) == 0

    def step_generate_report(self) -> bool:
        """
        Step 5: Generate final report.
        Summarizes all check results and optionally saves to file.
        """
        print("\n" + "=" * 63)
        print(" STEP 5: Health Check Report")
        print("=" * 63)

        self._debug_print("Generating report...")
        self._debug_print(f"Total results collected: {len(self.check_results)}")

        if not self.check_results:
            print("[INFO] No check results to report")
            return True

        # Summary statistics
        total = len(self.check_results)
        passed = len([r for r in self.check_results if r.status == CheckStatus.PASSED])
        failed = len([r for r in self.check_results if r.status == CheckStatus.FAILED])
        skipped = len([r for r in self.check_results if r.status == CheckStatus.SKIPPED])
        errors = len([r for r in self.check_results if r.status == CheckStatus.ERROR])

        critical_failures = [r for r in self.check_results
                            if r.status == CheckStatus.FAILED and r.severity == Severity.CRITICAL]
        warnings = [r for r in self.check_results
                   if r.status == CheckStatus.FAILED and r.severity == Severity.WARNING]

        print(f"\n  Total Checks Run:    {total}")
        print(f"  Passed:              {passed}")
        print(f"  Failed:              {failed}")
        print(f"    - Critical:        {len(critical_failures)}")
        print(f"    - Warning:         {len(warnings)}")
        print(f"  Skipped:             {skipped}")
        print(f"  Errors:              {errors}")

        if critical_failures:
            print("\n  CRITICAL FAILURES:")
            for r in critical_failures:
                node_str = f" ({r.node})" if r.node else ""
                print(f"    [CRIT] {r.check_id}{node_str}")
                print(f"           {r.message[:70]}")

        if warnings:
            print("\n  WARNINGS:")
            for r in warnings[:10]:
                node_str = f" ({r.node})" if r.node else ""
                print(f"    [WARN] {r.check_id}{node_str}: {r.message[:50]}")
            if len(warnings) > 10:
                print(f"    ... and {len(warnings) - 10} more warnings")

        # Save report to file
        report_file = self.config_dir / f"health_check_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total': total,
                'passed': passed,
                'failed': failed,
                'skipped': skipped,
                'errors': errors,
                'critical_count': len(critical_failures),
                'warning_count': len(warnings)
            },
            'results': [
                {
                    'check_id': r.check_id,
                    'node': r.node,
                    'status': r.status.value,
                    'severity': r.severity.value,
                    'message': r.message,
                    'description': r.description
                }
                for r in self.check_results
            ]
        }

        with open(report_file, 'w') as f:
            yaml.dump(report_data, f, default_flow_style=False)

        print(f"\n  Report saved: {report_file}")

        return len(critical_failures) == 0

    def run_all_checks(self, force_rediscover: bool = False,
                       skip_steps: list = None) -> int:
        """
        Run all health checks in sequence.
        Returns exit code (0 = success, non-zero = failure).
        """
        self.print_banner()
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Config directory: {self.config_dir}")

        skip_steps = skip_steps or []
        results = {}

        # Step 1: Access Discovery (required)
        if 'access' not in skip_steps:
            results['access'] = self.step_access_discovery(force=force_rediscover)
            if not results['access']:
                print("\n[ABORT] Cannot proceed without accessible nodes.")
                return 1

        # Step 2: Cluster Config Check
        if 'config' not in skip_steps:
            results['config'] = self.step_cluster_config_check()

        # Step 3: Pacemaker Check
        if 'pacemaker' not in skip_steps:
            results['pacemaker'] = self.step_pacemaker_check()

        # Step 4: SAP Check
        if 'sap' not in skip_steps:
            results['sap'] = self.step_sap_check()

        # Step 5: Generate Report
        if 'report' not in skip_steps:
            results['report'] = self.step_generate_report()

        # Final summary
        print("\n" + "=" * 63)
        print(" Health Check Complete")
        print("=" * 63)
        print(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        failed = [step for step, success in results.items() if not success]
        if failed:
            print(f"[WARNING] Failed steps: {', '.join(failed)}")
            return 1

        print("[OK] All checks passed")
        return 0


def main():
    parser = argparse.ArgumentParser(
        description='SAP Pacemaker Cluster Health Check Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s hana03                   Auto-discover cluster from hana03 and check all members
  %(prog)s -d hana03                Same with debug output
  %(prog)s --access-only hana03     Only test access (discover cluster members)
  %(prog)s -g sap_cluster           Only check hosts in Ansible group 'sap_cluster'
  %(prog)s                          Run full health check (all Ansible inventory hosts)
  %(prog)s --show-config            Show current configuration
  %(prog)s -H hosts.txt             Use custom hosts file
  %(prog)s -s /path/to/sosreports   Use SOSreport directory
        """
    )

    # Input sources
    parser.add_argument(
        'hosts',
        nargs='*',
        help='Hostname(s) to check (e.g., hana01 hana02)'
    )
    parser.add_argument(
        '--hosts-file', '-H',
        help='File containing list of hosts (one per line)'
    )
    parser.add_argument(
        '--sosreport-dir', '-s',
        help='Directory containing SOSreport archives/directories'
    )
    parser.add_argument(
        '--group', '-g',
        help='Only check hosts from this Ansible inventory group'
    )
    parser.add_argument(
        '--config-dir', '-c',
        help='Directory to store configuration (default: script directory)'
    )

    # Actions
    parser.add_argument(
        '--access-only', '-a',
        action='store_true',
        help='Only run access discovery step'
    )
    parser.add_argument(
        '--show-config', '-S',
        action='store_true',
        help='Display current configuration and exit'
    )
    parser.add_argument(
        '--delete-config', '-D',
        action='store_true',
        help='Delete configuration file to restart investigation'
    )
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Force rediscovery (ignore existing config)'
    )

    # Performance
    parser.add_argument(
        '--workers', '-w',
        type=int,
        default=10,
        help='Number of parallel workers (default: 10)'
    )

    # Rules
    parser.add_argument(
        '--rules-path', '-r',
        help='Path to CHK_*.yaml rules directory (default: cluster_health_check rules)'
    )
    parser.add_argument(
        '--list-rules', '-L',
        action='store_true',
        help='List available health check rules and exit'
    )

    # Skip options
    parser.add_argument(
        '--skip',
        nargs='+',
        choices=['access', 'config', 'pacemaker', 'sap', 'report'],
        help='Skip specific steps'
    )

    # Debug option
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug mode (show config files used and step progress)'
    )

    args = parser.parse_args()

    # Determine config directory
    config_dir = Path(args.config_dir) if args.config_dir else SCRIPT_DIR
    config_path = config_dir / AccessDiscovery.CONFIG_FILE

    # Handle hosts provided on command line
    hosts_file = args.hosts_file
    temp_hosts_file = None
    if args.hosts and not hosts_file:
        # Create temporary hosts file from command line arguments
        import tempfile
        temp_hosts_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        for host in args.hosts:
            temp_hosts_file.write(f"{host}\n")
        temp_hosts_file.close()
        hosts_file = temp_hosts_file.name
        if args.debug:
            print(f"[DEBUG] Created temp hosts file: {hosts_file}")
            print(f"[DEBUG] Hosts: {', '.join(args.hosts)}")

    # Handle show-config action
    if args.show_config:
        show_config(config_path)
        sys.exit(0)

    # Handle delete-config action
    if args.delete_config:
        delete_config(config_path)
        sys.exit(0)

    # Handle list-rules action
    if args.list_rules:
        rules_path = args.rules_path or ClusterHealthCheck.DEFAULT_RULES_PATH
        engine = RulesEngine(rules_path=rules_path)
        engine.load_rules()
        print("\n" + "=" * 63)
        print(" Available Health Check Rules")
        print("=" * 63)
        print(f"\nRules path: {rules_path}\n")
        print(f"{'Check ID':<30} {'Severity':<10} Description")
        print("-" * 63)
        for rule in engine.rules:
            print(f"{rule.check_id:<30} {rule.severity:<10} {rule.description[:40]}")
        print(f"\nTotal: {len(engine.rules)} rules")
        sys.exit(0)

    # Create health check instance
    health_check = ClusterHealthCheck(
        config_dir=str(config_dir),
        sosreport_dir=args.sosreport_dir,
        hosts_file=hosts_file,
        workers=args.workers,
        rules_path=args.rules_path,
        debug=args.debug,
        ansible_group=args.group
    )

    def cleanup_temp_file():
        """Clean up temporary hosts file if created."""
        if temp_hosts_file:
            try:
                os.unlink(temp_hosts_file.name)
            except Exception:
                pass

    try:
        if args.access_only:
            # Only run access discovery
            health_check.print_banner()
            success = health_check.step_access_discovery(force=args.force)
            cleanup_temp_file()
            sys.exit(0 if success else 1)
        else:
            # Run all checks
            exit_code = health_check.run_all_checks(
                force_rediscover=args.force,
                skip_steps=args.skip
            )
            cleanup_temp_file()
            sys.exit(exit_code)

    except KeyboardInterrupt:
        cleanup_temp_file()
        print("\n\n[INTERRUPTED] Health check aborted by user.")
        sys.exit(130)


if __name__ == '__main__':
    main()
