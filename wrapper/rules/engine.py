#!/usr/bin/env python3
"""
Rules Engine for SAP Pacemaker Cluster Health Check

Loads and executes health check rules from YAML files.
Supports both live command execution and SOSreport parsing.
"""

import os
import re
import yaml
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum

# Python 3.6 compatibility for dataclasses
try:
    from dataclasses import dataclass, field
except ImportError:
    # Fallback for Python < 3.7
    def field(default=None, default_factory=None):
        return default_factory() if default_factory else default

    def dataclass(cls):
        """Simple dataclass decorator fallback"""
        def __init__(self, **kwargs):
            # Set defaults from class annotations first
            if hasattr(cls, '__annotations__'):
                for name in cls.__annotations__:
                    default = getattr(cls, name, None)
                    setattr(self, name, default)
            # Override with provided kwargs
            for key, value in kwargs.items():
                setattr(self, key, value)
            # Call __post_init__ if defined
            if hasattr(self, '__post_init__'):
                self.__post_init__()
        cls.__init__ = __init__
        return cls


class Severity(Enum):
    """Check severity levels."""
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class CheckStatus(Enum):
    """Check result status."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


@dataclass
class CheckResult:
    """Result of a single health check."""
    check_id: str = None
    description: str = None
    status: CheckStatus = None
    severity: Severity = None
    message: str = None
    details: Dict[str, Any] = None
    node: Optional[str] = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


@dataclass
class RuleDefinition:
    """Parsed rule definition from YAML."""
    check_id: str = None
    version: str = None
    severity: str = None
    description: str = None
    enabled: bool = True
    source_definitions: Dict[str, Any] = None
    parser: Dict[str, Any] = None
    validation_logic: Dict[str, Any] = None
    topology_filter: Optional[str] = None
    raw_yaml: Dict[str, Any] = None

    def __post_init__(self):
        if self.raw_yaml is None:
            self.raw_yaml = {}


class RulesEngine:
    """Engine for loading and executing health check rules."""

    # TODO: Add CHK_*.yaml health check rules to this directory
    DEFAULT_RULES_PATH = str(Path(__file__).parent / "health_checks")
    CMD_TIMEOUT = 15  # Reduced from 30 to avoid long waits
    MAX_WORKERS = 5

    def __init__(self, rules_path: str = None, access_config: dict = None):
        self.rules_path = Path(rules_path) if rules_path else Path(self.DEFAULT_RULES_PATH)
        self.access_config = access_config or {}
        self.rules: List[RuleDefinition] = []
        self.results: List[CheckResult] = []

    def load_rules(self) -> List[RuleDefinition]:
        """Load all CHK_*.yaml rule files."""
        self.rules = []

        if not self.rules_path.exists():
            print(f"[WARNING] Rules path does not exist: {self.rules_path}")
            return self.rules

        rule_files = sorted(self.rules_path.glob("CHK_*.yaml"))
        print(f"Found {len(rule_files)} rule files in {self.rules_path}")

        for rule_file in rule_files:
            try:
                with open(rule_file, 'r') as f:
                    data = yaml.safe_load(f)

                if not data or not data.get('enabled', True):
                    print(f"  [SKIP] {rule_file.name} (disabled)")
                    continue

                rule = RuleDefinition(
                    check_id=data.get('check_id', rule_file.stem),
                    version=data.get('version', '1.0'),
                    severity=data.get('severity', 'WARNING'),
                    description=data.get('description', ''),
                    enabled=data.get('enabled', True),
                    source_definitions=data.get('source_definitions', {}),
                    parser=data.get('parser', {}),
                    validation_logic=data.get('validation_logic', {}),
                    topology_filter=data.get('topology_filter'),
                    raw_yaml=data
                )
                self.rules.append(rule)
                print(f"  [LOAD] {rule.check_id}: {rule.description[:50]}...")

            except Exception as e:
                print(f"  [ERROR] Failed to load {rule_file.name}: {e}")

        return self.rules

    def list_rules(self) -> List[Dict[str, str]]:
        """Return a summary list of loaded rules."""
        return [
            {
                'check_id': r.check_id,
                'severity': r.severity,
                'description': r.description,
                'enabled': r.enabled
            }
            for r in self.rules
        ]

    def _execute_command(self, cmd: str, node: str = None,
                        method: str = 'ssh', user: str = None) -> Tuple[bool, str]:
        """Execute a command locally, via SSH, or via Ansible."""
        try:
            if method == 'local':
                # Execute command locally (when running on the cluster node itself)
                full_cmd = cmd
            elif node and method == 'ssh':
                ssh_user = user or os.environ.get('USER', 'root')
                # Escape single quotes in command: replace ' with '\''
                escaped_cmd = cmd.replace("'", "'\"'\"'")
                full_cmd = f"ssh -o BatchMode=yes -o ConnectTimeout=10 {ssh_user}@{node} '{escaped_cmd}'"
            elif node and method == 'ansible':
                escaped_cmd = cmd.replace("'", "'\"'\"'")
                full_cmd = f"ansible {node} -m shell -a '{escaped_cmd}' -o"
            else:
                full_cmd = cmd

            result = subprocess.run(
                full_cmd,
                shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=self.CMD_TIMEOUT
            )

            output = result.stdout
            if method == 'ansible' and node:
                # Parse Ansible output - extract actual command output
                if '|' in output and '>>' in output:
                    output = output.split('>>', 1)[-1].strip()

            return result.returncode == 0, output

        except subprocess.TimeoutExpired:
            return False, f"Command timed out after {self.CMD_TIMEOUT}s"
        except Exception as e:
            return False, str(e)

    def _read_sosreport(self, sos_path: str, node: str, sos_base: str) -> Tuple[bool, str]:
        """Read data from SOSreport directory."""
        # Build full path
        node_sos = Path(sos_base) / node
        if not node_sos.exists():
            # Try to find matching sosreport directory
            for item in Path(sos_base).iterdir():
                if item.is_dir() and node in item.name:
                    node_sos = item
                    break

        file_path = node_sos / sos_path
        if file_path.exists():
            try:
                with open(file_path, 'r') as f:
                    return True, f.read()
            except Exception as e:
                return False, str(e)

        return False, f"File not found: {file_path}"

    def _parse_output(self, output: str, parser_config: Dict) -> Dict[str, Any]:
        """Parse command output using configured parser."""
        parsed = {}

        if parser_config.get('type') != 'regex':
            return {'raw': output}

        patterns = parser_config.get('search_patterns', [])
        flags = re.MULTILINE if parser_config.get('multiline', False) else 0

        for pattern in patterns:
            name = pattern.get('name')
            regex = pattern.get('regex')
            group = pattern.get('group', 0)

            if not name or not regex:
                continue

            try:
                match = re.search(regex, output, flags)
                if match:
                    if group == 0:
                        parsed[name] = match.group(0)
                    else:
                        parsed[name] = match.group(group) if group <= len(match.groups()) else None
                else:
                    parsed[name] = None
            except Exception as e:
                parsed[name] = None
                parsed[f'{name}_error'] = str(e)

        return parsed

    def _evaluate_expectation(self, parsed: Dict, expectation: Dict) -> Tuple[bool, str]:
        """Evaluate a single expectation against parsed data."""
        key = expectation.get('key')
        operator = expectation.get('operator')
        expected = expectation.get('value')
        message = expectation.get('message', f"Check failed for {key}")

        actual = parsed.get(key)

        if operator == 'exists':
            if expected:
                passed = actual is not None
            else:
                passed = actual is None
        elif operator == 'not_exists':
            passed = actual is None
        elif operator == 'eq':
            passed = actual == expected
        elif operator == 'ne':
            passed = actual != expected
        elif operator == 'in':
            passed = actual in expected if isinstance(expected, list) else actual == expected
        elif operator == 'not_in':
            passed = actual not in expected if isinstance(expected, list) else actual != expected
        elif operator == 'contains':
            passed = expected in str(actual) if actual else False
        elif operator == 'regex':
            passed = bool(re.search(expected, str(actual))) if actual else False
        elif operator == 'gt':
            try:
                passed = float(actual) > float(expected)
            except (TypeError, ValueError):
                passed = False
        elif operator == 'lt':
            try:
                passed = float(actual) < float(expected)
            except (TypeError, ValueError):
                passed = False
        else:
            passed = False
            message = f"Unknown operator: {operator}"

        return passed, message

    def _check_command_available(self, cmd: str, node: str, method: str, user: str = None) -> tuple:
        """
        Quick check if the primary command in a pipeline is available.
        Returns (available: bool, reason: str)
        """
        # Extract first command from pipeline
        first_cmd = cmd.split('|')[0].split(';')[0].split('&&')[0].strip()

        # Skip check for built-in commands and common utilities
        builtins = ['grep', 'cat', 'echo', 'awk', 'sed', 'head', 'tail', 'cut', 'tr', 'sort', 'timeout']
        cmd_name = first_cmd.split()[0] if first_cmd else ''

        if cmd_name in builtins or cmd_name.startswith('/'):
            return True, "builtin/path"

        # Check if command exists (locally or on remote node)
        check_cmd = f"command -v {cmd_name} >/dev/null 2>&1 && echo 'OK' || echo 'MISSING'"
        success, output = self._execute_command(check_cmd, node, method, user)

        if success and 'OK' in output:
            return True, "available"
        elif 'MISSING' in output:
            return False, f"Command '{cmd_name}' not found on {node}"
        else:
            # If check failed, assume command might be available
            return True, "unknown"

    def _run_check_on_node(self, rule: RuleDefinition, node: str,
                          method: str, user: str = None,
                          sos_base: str = None) -> CheckResult:
        """Run a single check on a specific node."""
        source_defs = rule.source_definitions

        # Get data based on access method
        if method == 'sosreport' and sos_base:
            sos_path = source_defs.get('sos_path')
            alternates = source_defs.get('sos_path_alternates', [])
            success, output = self._read_sosreport(sos_path, node, sos_base)
            if not success:
                for alt_path in alternates:
                    success, output = self._read_sosreport(alt_path, node, sos_base)
                    if success:
                        break
        else:
            cmd = source_defs.get('live_cmd')
            if not cmd:
                return CheckResult(
                    check_id=rule.check_id,
                    description=rule.description,
                    status=CheckStatus.SKIPPED,
                    severity=Severity[rule.severity],
                    message="No live command defined",
                    node=node
                )

            # Pre-flight check: verify primary command is available
            preflight = source_defs.get('preflight_check', True)
            if preflight:
                cmd_available, reason = self._check_command_available(cmd, node, method, user)
                if not cmd_available:
                    return CheckResult(
                        check_id=rule.check_id,
                        description=rule.description,
                        status=CheckStatus.SKIPPED,
                        severity=Severity[rule.severity],
                        message=f"Skipped: {reason}",
                        node=node
                    )

            success, output = self._execute_command(cmd, node, method, user)

        if not success:
            return CheckResult(
                check_id=rule.check_id,
                description=rule.description,
                status=CheckStatus.ERROR,
                severity=Severity[rule.severity],
                message=f"Failed to get data: {output[:100]}",
                node=node
            )

        # Parse output
        parsed = self._parse_output(output, rule.parser)

        # Evaluate expectations
        validation = rule.validation_logic
        expectations = validation.get('expectations', [])

        failed_expectations = []
        for exp in expectations:
            passed, message = self._evaluate_expectation(parsed, exp)
            if not passed:
                failed_expectations.append({
                    'key': exp.get('key'),
                    'severity': exp.get('severity', rule.severity),
                    'message': message
                })

        if failed_expectations:
            # Use highest severity from failed expectations
            max_severity = rule.severity
            for fe in failed_expectations:
                if fe['severity'] == 'CRITICAL':
                    max_severity = 'CRITICAL'
                    break
                elif fe['severity'] == 'WARNING' and max_severity != 'CRITICAL':
                    max_severity = 'WARNING'

            return CheckResult(
                check_id=rule.check_id,
                description=rule.description,
                status=CheckStatus.FAILED,
                severity=Severity[max_severity],
                message="; ".join(fe['message'] for fe in failed_expectations),
                details={'parsed': parsed, 'failed': failed_expectations},
                node=node
            )

        return CheckResult(
            check_id=rule.check_id,
            description=rule.description,
            status=CheckStatus.PASSED,
            severity=Severity[rule.severity],
            message="All checks passed",
            details={'parsed': parsed},
            node=node
        )

    def run_check(self, rule: RuleDefinition, nodes: Dict[str, dict]) -> List[CheckResult]:
        """Run a check across all nodes (multithreaded)."""
        results = []
        scope = rule.validation_logic.get('scope', 'per_node')

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            futures = {}

            for node_name, node_info in nodes.items():
                method = node_info.get('preferred_method')
                if not method:
                    results.append(CheckResult(
                        check_id=rule.check_id,
                        description=rule.description,
                        status=CheckStatus.SKIPPED,
                        severity=Severity[rule.severity],
                        message="No access method available",
                        node=node_name
                    ))
                    continue

                user = node_info.get('ssh_user') or node_info.get('ansible_user')
                sos_base = self.access_config.get('sosreport_directory')

                future = executor.submit(
                    self._run_check_on_node,
                    rule, node_name, method, user, sos_base
                )
                futures[future] = node_name

            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append(CheckResult(
                        check_id=rule.check_id,
                        description=rule.description,
                        status=CheckStatus.ERROR,
                        severity=Severity[rule.severity],
                        message=str(e),
                        node=futures[future]
                    ))

        return results

    def run_all_checks(self, nodes: Dict[str, dict]) -> List[CheckResult]:
        """Run all loaded checks on all nodes."""
        self.results = []

        if not self.rules:
            self.load_rules()

        print(f"\nRunning {len(self.rules)} checks on {len(nodes)} node(s)...")

        for rule in self.rules:
            print(f"\n  [{rule.severity}] {rule.check_id}: {rule.description[:40]}...")
            check_results = self.run_check(rule, nodes)

            for result in check_results:
                self.results.append(result)
                status_icon = {
                    CheckStatus.PASSED: "✓",
                    CheckStatus.FAILED: "✗",
                    CheckStatus.SKIPPED: "○",
                    CheckStatus.ERROR: "!"
                }.get(result.status, "?")
                node_str = f" ({result.node})" if result.node else ""
                print(f"    {status_icon} {result.status.value}{node_str}: {result.message[:60]}")

        return self.results

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all check results."""
        summary = {
            'total': len(self.results),
            'passed': 0,
            'failed': 0,
            'skipped': 0,
            'errors': 0,
            'critical_failures': [],
            'warnings': []
        }

        for result in self.results:
            if result.status == CheckStatus.PASSED:
                summary['passed'] += 1
            elif result.status == CheckStatus.FAILED:
                summary['failed'] += 1
                if result.severity == Severity.CRITICAL:
                    summary['critical_failures'].append(result)
                else:
                    summary['warnings'].append(result)
            elif result.status == CheckStatus.SKIPPED:
                summary['skipped'] += 1
            elif result.status == CheckStatus.ERROR:
                summary['errors'] += 1

        return summary

    def print_summary(self):
        """Print formatted summary of results."""
        summary = self.get_summary()

        print("\n" + "=" * 63)
        print(" Health Check Results Summary")
        print("=" * 63)
        print(f"  Total checks:  {summary['total']}")
        print(f"  Passed:        {summary['passed']}")
        print(f"  Failed:        {summary['failed']}")
        print(f"  Skipped:       {summary['skipped']}")
        print(f"  Errors:        {summary['errors']}")

        if summary['critical_failures']:
            print("\n  CRITICAL FAILURES:")
            for r in summary['critical_failures']:
                print(f"    - [{r.check_id}] {r.message[:50]}")

        if summary['warnings']:
            print("\n  WARNINGS:")
            for r in summary['warnings'][:5]:  # Show first 5
                print(f"    - [{r.check_id}] {r.message[:50]}")
            if len(summary['warnings']) > 5:
                print(f"    ... and {len(summary['warnings']) - 5} more")
