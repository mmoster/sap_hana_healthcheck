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
                 debug: bool = False, ansible_group: str = None, skip_ansible: bool = False,
                 cluster_name: str = None):
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
        self.cluster_name = cluster_name

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
            skip_ansible=self.skip_ansible,
            cluster_name=self.cluster_name
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

        # Show cluster and nodes summary
        node_names = list(self.access_config.nodes.keys())
        cluster_name = None
        for cname, cinfo in self.access_config.clusters.items():
            if any(n in node_names for n in cinfo.get('nodes', [])):
                cluster_name = cname
                break

        print("\n" + "-" * 63)
        if cluster_name:
            print(f"  Cluster:  {cluster_name}")
        print(f"  Nodes:    {', '.join(sorted(node_names))}")
        print("-" * 63)
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

    def _run_rules_parallel(self, rules: list, nodes: dict) -> list:
        """Run multiple rules in parallel using thread pool."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        all_results = []
        max_parallel_rules = min(len(rules), 4)  # Max 4 rules in parallel

        with ThreadPoolExecutor(max_workers=max_parallel_rules) as executor:
            futures = {}
            for rule in rules:
                future = executor.submit(self.rules_engine.run_check, rule, nodes)
                futures[future] = rule.check_id

            for future in as_completed(futures):
                check_id = futures[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                    self._debug_print(f"Completed: {check_id} ({len(results)} results)")
                except Exception as e:
                    self._debug_print(f"Error in {check_id}: {e}")

        return all_results

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
        print(f"Running {len(rules_to_run)} cluster configuration checks (parallel)...")

        # Run rules in parallel
        results = self._run_rules_parallel(rules_to_run, nodes)
        self.check_results.extend(results)

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
        print(f"Running {len(rules_to_run)} Pacemaker/Corosync checks (parallel)...")

        # Run rules in parallel
        results = self._run_rules_parallel(rules_to_run, nodes)
        self.check_results.extend(results)

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
        print(f"Running {len(rules_to_run)} SAP-specific checks (parallel)...")

        # Run rules in parallel
        results = self._run_rules_parallel(rules_to_run, nodes)
        self.check_results.extend(results)

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

        # Show cluster and nodes info
        if self.access_config:
            nodes = list(self.access_config.nodes.keys())
            # Find cluster name from config
            cluster_name = None
            for cname, cinfo in self.access_config.clusters.items():
                if set(cinfo.get('nodes', [])) == set(nodes) or \
                   any(n in nodes for n in cinfo.get('nodes', [])):
                    cluster_name = cname
                    break

            if cluster_name:
                print(f"Cluster: {cluster_name}")
            print(f"Nodes checked: {', '.join(sorted(nodes))}")

        # Show all steps with status
        print("\nSteps completed:")
        step_names = {
            'access': 'Access Discovery',
            'config': 'Cluster Configuration',
            'pacemaker': 'Pacemaker/Corosync',
            'sap': 'SAP HANA',
            'report': 'Report Generation'
        }
        for step, success in results.items():
            status = "[OK]" if success else "[FAIL]"
            name = step_names.get(step, step)
            print(f"  {status} {name}")

        failed = [step for step, success in results.items() if not success]
        if failed:
            print(f"\n[WARNING] Failed steps: {', '.join(failed)}")

        # Show next steps
        self._print_next_steps(results)

        if failed:
            return 1

        print("[OK] All checks passed")
        return 0

    def _print_next_steps(self, results: dict):
        """Print suggested next steps based on results."""
        print("\n" + "-" * 63)
        print(" Next Steps")
        print("-" * 63)

        # Check what was done and suggest next actions
        if not results.get('access'):
            print("""
  Access discovery failed. Try:
    ./cluster_health_check.py --debug hana01    # Debug with specific node
    ./cluster_health_check.py -s /path/to/sos   # Use SOSreports instead
""")
            return

        # Get results from rules engine if available
        all_results = getattr(self.rules_engine, 'results', []) if self.rules_engine else []

        if all_results:
            # Analyze results
            critical = [r for r in all_results if hasattr(r, 'status') and
                       str(r.status) == 'CheckStatus.FAILED' and
                       hasattr(r, 'severity') and str(r.severity) == 'Severity.CRITICAL']
            warnings = [r for r in all_results if hasattr(r, 'status') and
                       str(r.status) == 'CheckStatus.FAILED' and
                       hasattr(r, 'severity') and str(r.severity) == 'Severity.WARNING']
            skipped = [r for r in all_results if hasattr(r, 'status') and
                      str(r.status) == 'CheckStatus.SKIPPED']

            if critical:
                print(f"""
  CRITICAL issues found ({len(critical)}). Review:
    - Check the report file for details
    - Address STONITH/fencing issues first
    - Verify quorum configuration
""")

            if warnings:
                print(f"  Warnings found ({len(warnings)}). Review report for details.")

            if skipped:
                print(f"  Skipped checks ({len(skipped)}). Some commands may not be available.")

        print("""
  Common next steps:
    ./cluster_health_check.py --show-config     # View current config
    ./cluster_health_check.py -f hana01         # Force re-discovery
    ./cluster_health_check.py --list-rules      # List all health checks
    ./cluster_health_check.py --guide           # Show detailed usage guide
""")

        print("  Documentation:")
        print("    SAP HANA Admin:  https://help.sap.com/docs/SAP_HANA_PLATFORM")
        print("    SAP HANA SR:     https://help.sap.com/docs/SAP_HANA_PLATFORM/6b94445c94ae495c83a19646e7c3fd56")
        print("    Red Hat HA:      https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_high_availability_clusters/")
        print("    Pacemaker:       https://clusterlabs.org/pacemaker/doc/")


def print_guide():
    """Print detailed usage guide."""
    print("""
===============================================================================
                    SAP Pacemaker Cluster Health Check - Guide
===============================================================================

QUICK START
-----------
  1. Check a live cluster (auto-discovers all members):
     ./cluster_health_check.py hana01

  2. Analyze SOSreports offline:
     ./cluster_health_check.py -s /path/to/sosreports/

  3. Show current configuration:
     ./cluster_health_check.py --show-config

WORKFLOW
--------
  Step 1: ACCESS DISCOVERY
    The tool first discovers how to access your nodes:
    - SSH direct access (preferred)
    - Ansible inventory
    - SOSreport directories

    Example: ./cluster_health_check.py --access-only hana01

  Step 2: CLUSTER DISCOVERY
    From the first reachable node, discovers all cluster members:
    - Uses: crm_node -l, pcs status nodes, corosync-cmapctl
    - Saves cluster name for future runs

    Example: ./cluster_health_check.py -C mycluster  # Use saved cluster

  Step 3: HEALTH CHECKS
    Runs all CHK_*.yaml rules against discovered nodes:
    - Cluster configuration (quorum, fencing, resources)
    - Pacemaker status (nodes, resources, failures)
    - SAP-specific (HANA SR status, hooks, systemd)

    Example: ./cluster_health_check.py --list-rules  # See all checks

  Step 4: REPORT GENERATION
    Generates YAML report with all findings:
    - Critical failures (must fix)
    - Warnings (should review)
    - Passed checks

COMMON USE CASES
----------------
  Live cluster check:
    ./cluster_health_check.py hana01 hana02

  SOSreport analysis (auto-extracts .tar.xz):
    ./cluster_health_check.py -s /path/to/sosreports/

  Debug mode (verbose output):
    ./cluster_health_check.py -d hana01

  Use saved cluster:
    ./cluster_health_check.py -C production_cluster

  Skip specific steps:
    ./cluster_health_check.py --skip sap report hana01

  Force re-discovery:
    ./cluster_health_check.py -f hana01

  Ansible inventory group:
    ./cluster_health_check.py -g sap_hana_cluster

OPTIONS REFERENCE
-----------------
  Input Sources:
    <hosts>           Hostnames to check (auto-discovers cluster)
    -H, --hosts-file  File with hostnames (one per line)
    -s, --sosreport   Directory with SOSreport archives
    -g, --group       Ansible inventory group filter
    -C, --cluster     Use saved cluster name

  Actions:
    -a, --access-only  Only run access discovery
    -S, --show-config  Show current configuration
    -D, --delete-config Delete config (fresh start)
    -L, --list-rules   List available health checks
    -G, --guide        Show this guide

  Modifiers:
    -d, --debug       Debug mode (verbose)
    -f, --force       Force re-discovery
    -w, --workers     Parallel workers (default: 10)
    -r, --rules-path  Custom rules directory

TROUBLESHOOTING
---------------
  No SSH access:
    - Check SSH keys: ssh-copy-id root@hana01
    - Try: ./cluster_health_check.py -d hana01  # Debug output

  Commands timing out:
    - Some SAP commands are slow, tool uses 15s timeout
    - Use SOSreports for offline analysis

  Wrong nodes discovered:
    - Specify nodes explicitly: ./cluster_health_check.py hana01 hana02
    - Use hosts file: ./cluster_health_check.py -H my_hosts.txt

DOCUMENTATION
-------------
  SAP HANA Platform:
    https://help.sap.com/docs/SAP_HANA_PLATFORM

  SAP HANA System Replication:
    https://help.sap.com/docs/SAP_HANA_PLATFORM/6b94445c94ae495c83a19646e7c3fd56

  SAP HANA Administration Guide:
    https://help.sap.com/docs/SAP_HANA_PLATFORM/6b94445c94ae495c83a19646e7c3fd56/330e5550b09d4f0f8b6cceb14a1f956d.html

  Red Hat HA Clusters:
    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_high_availability_clusters/

  Red Hat SAP HANA HA:
    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_for_sap_solutions/8/

  Pacemaker Documentation:
    https://clusterlabs.org/pacemaker/doc/

  ClusterLabs Wiki:
    https://wiki.clusterlabs.org/

HEALTH CHECK RULES
------------------
  Rules are defined in YAML files (CHK_*.yaml). Each rule specifies:
    - Command to run (live_cmd) or SOSreport path (sos_path)
    - Parser to extract values (regex patterns)
    - Validation logic (expectations)

  Custom rules: ./cluster_health_check.py -r /path/to/my_rules/

===============================================================================
""")


def print_suggestions(step: str):
    """Print detailed suggestions for a specific step."""
    suggestions = {
        'access': """
===============================================================================
                         ACCESS DISCOVERY - Suggestions
===============================================================================

PURPOSE
-------
  Discover how to connect to cluster nodes (SSH, Ansible, or SOSreports)

COMMON ISSUES & SOLUTIONS
-------------------------

  1. SSH Connection Failed
     - Check SSH keys: ssh-copy-id root@hana01
     - Test manually: ssh -o BatchMode=yes root@hana01 hostname
     - Check firewall: firewall-cmd --list-all

  2. Permission Denied
     - Ensure root access or sudo without password
     - Check /etc/ssh/sshd_config for PermitRootLogin

  3. Host Not Found
     - Verify hostname in /etc/hosts or DNS
     - Try IP address: ./cluster_health_check.py 192.168.1.100

  4. Ansible Inventory Issues
     - Check inventory: ansible-inventory --list
     - Use specific group: ./cluster_health_check.py -g sap_cluster
     - Skip Ansible: specify hosts directly

COMMANDS TO TRY
---------------
  # Debug connection
  ./cluster_health_check.py -d --access-only hana01

  # Use SOSreports instead
  ./cluster_health_check.py -s /path/to/sosreports/

  # Specify hosts manually
  ./cluster_health_check.py hana01 hana02

DOCUMENTATION
-------------
  SSH: https://man.openbsd.org/ssh
  Ansible: https://docs.ansible.com/ansible/latest/inventory_guide/
""",
        'config': """
===============================================================================
                      CLUSTER CONFIGURATION - Suggestions
===============================================================================

PURPOSE
-------
  Verify cluster configuration (quorum, corosync, resources)

CHECKS PERFORMED
----------------
  CHK_NODE_STATUS        - All nodes online
  CHK_CLUSTER_QUORUM     - Quorum is established
  CHK_QUORUM_CONFIG      - Quorum settings correct (expected_votes, two_node)
  CHK_CLONE_CONFIG       - Clone resources properly configured
  CHK_SETUP_VALIDATION   - Basic setup validation
  CHK_CIB_TIME_SYNC      - CIB timestamps synchronized
  CHK_PACKAGE_CONSISTENCY - Package versions match across nodes

COMMON ISSUES & SOLUTIONS
-------------------------

  1. Expected Votes Not Configured
     - Check: grep expected_votes /etc/corosync/corosync.conf
     - Fix: Set expected_votes in quorum section
     - For 2-node: also set two_node: 1 and wait_for_all: 0

  2. Quorum Not Established
     - Check: corosync-quorumtool -s
     - Verify all nodes are online: crm_mon -1
     - Check corosync: systemctl status corosync

  3. No Designated Controller (DC)
     - Cluster may not be running: pcs status
     - Start cluster: pcs cluster start --all

COMMANDS TO CHECK
-----------------
  # Cluster status
  pcs status
  crm_mon -1

  # Quorum status
  corosync-quorumtool -s

  # Configuration
  pcs config show
  crm configure show

DOCUMENTATION
-------------
  Red Hat HA Quorum:
    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_high_availability_clusters/assembly_configuring-cluster-quorum-configuring-and-managing-high-availability-clusters

  Corosync Configuration:
    https://clusterlabs.org/pacemaker/doc/2.1/Pacemaker_Explained/html/cluster-options.html
""",
        'pacemaker': """
===============================================================================
                       PACEMAKER/COROSYNC - Suggestions
===============================================================================

PURPOSE
-------
  Check Pacemaker resources, STONITH/fencing, and cluster health

CHECKS PERFORMED
----------------
  CHK_STONITH_CONFIG     - STONITH is enabled and configured
  CHK_RESOURCE_STATUS    - All resources running
  CHK_RESOURCE_FAILURES  - No resource failures
  CHK_ALERT_FENCING      - Fencing alerts configured
  CHK_MASTER_SLAVE_ROLES - Master/slave roles correct
  CHK_MAJORITY_MAKER     - Majority maker for 2-node clusters

COMMON ISSUES & SOLUTIONS
-------------------------

  1. STONITH Not Configured
     - CRITICAL: Production clusters MUST have STONITH
     - Check: pcs property show stonith-enabled
     - Configure fencing agent for your hardware/cloud

  2. Resource Failures
     - Check: pcs resource failcount show
     - Clear failures: pcs resource cleanup <resource>
     - Check logs: journalctl -u pacemaker

  3. Resources Not Running
     - Check constraints: pcs constraint show
     - Check resource config: pcs resource show <resource>
     - Start resource: pcs resource enable <resource>

  4. Split-Brain Risk
     - Ensure STONITH is working
     - Test fencing: pcs stonith fence <node> --off

COMMANDS TO CHECK
-----------------
  # Resource status
  pcs status resources
  crm_mon -1 -rf

  # STONITH status
  pcs stonith status
  pcs property show stonith-enabled

  # Resource failures
  pcs resource failcount show

  # Fencing history
  pcs stonith history

DOCUMENTATION
-------------
  Red Hat Fencing:
    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_high_availability_clusters/assembly_configuring-fencing-configuring-and-managing-high-availability-clusters

  Pacemaker Resources:
    https://clusterlabs.org/pacemaker/doc/2.1/Pacemaker_Explained/html/resources.html
""",
        'sap': """
===============================================================================
                           SAP HANA - Suggestions
===============================================================================

PURPOSE
-------
  Check SAP HANA System Replication and SAP-specific configurations

CHECKS PERFORMED
----------------
  CHK_HANA_SR_STATUS     - HANA System Replication active
  CHK_SITE_ROLES         - Primary/secondary sites correct
  CHK_REPLICATION_MODE   - Sync mode (sync/syncmem recommended)
  CHK_HADR_HOOKS         - HA/DR hooks configured
  CHK_HANA_AUTOSTART     - Autostart disabled (Pacemaker manages)
  CHK_SYSTEMD_SAP        - SAP systemd services correct

COMMON ISSUES & SOLUTIONS
-------------------------

  1. System Replication Not Active
     - Check: SAPHanaSR-showAttr
     - Verify SR status: hdbnsutil -sr_state
     - Check secondary registered: hdbnsutil -sr_register --help

  2. Wrong Replication Mode (async)
     - Risk: Data loss on failover
     - Change to sync: hdbnsutil -sr_changemode --mode=sync

  3. Multiple Primary Sites (Split-Brain)
     - CRITICAL: Immediate attention required
     - Check: SAPHanaSR-showAttr | grep -i prim
     - May need manual intervention

  4. HA/DR Hooks Not Configured
     - Required for automatic failover
     - Configure in global.ini: [ha_dr_provider_*]

  5. Autostart Enabled
     - Should be disabled when using Pacemaker
     - Check: grep Autostart /usr/sap/<SID>/SYS/profile/*

COMMANDS TO CHECK
-----------------
  # HANA SR status (run as <sid>adm)
  SAPHanaSR-showAttr
  hdbnsutil -sr_state

  # Pacemaker HANA resources
  pcs resource show SAPHana*
  crm_mon -A1 | grep -i hana

  # HANA processes
  sapcontrol -nr <instance> -function GetProcessList

DOCUMENTATION
-------------
  SAP HANA System Replication:
    https://help.sap.com/docs/SAP_HANA_PLATFORM/6b94445c94ae495c83a19646e7c3fd56

  SAP HANA HA/DR Providers:
    https://help.sap.com/docs/SAP_HANA_PLATFORM/6b94445c94ae495c83a19646e7c3fd56/1367c8fdefaa4808a7485b09f7a62949.html

  Red Hat SAP HANA HA:
    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_for_sap_solutions/8/
"""
    }

    if step == 'all':
        for s in ['access', 'config', 'pacemaker', 'sap']:
            print(suggestions.get(s, f"No suggestions available for '{s}'"))
    else:
        print(suggestions.get(step, f"No suggestions available for '{step}'"))


def main():
    parser = argparse.ArgumentParser(
        description='SAP Pacemaker Cluster Health Check Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s hana03                   Auto-discover cluster from hana03 and check all members
  %(prog)s -C mycluster             Use previously discovered cluster 'mycluster'
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
        '--cluster', '-C',
        help='Use saved cluster by name (from previous discovery)'
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

    # Guide option
    parser.add_argument(
        '--guide', '-G',
        action='store_true',
        help='Show detailed usage guide with examples and next steps'
    )

    # Suggest option
    parser.add_argument(
        '--suggest',
        choices=['access', 'config', 'pacemaker', 'sap', 'all'],
        help='Show suggestions and documentation for a specific step'
    )

    args = parser.parse_args()

    # Handle guide action
    if args.guide:
        print_guide()
        sys.exit(0)

    # Handle suggest action
    if args.suggest:
        print_suggestions(args.suggest)
        sys.exit(0)

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
        ansible_group=args.group,
        cluster_name=args.cluster
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
