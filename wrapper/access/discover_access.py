#!/usr/bin/env python3
"""
SAP Pacemaker Cluster Health Check - Access Discovery Module

Discovers available access methods to cluster nodes:
1. SSH direct access (preferred)
2. Ansible inventory
3. SOSreport files

Results are stored in a YAML config file for incremental investigation.
"""

import os
import sys
import subprocess
import yaml
import argparse
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Any
from datetime import datetime

# Python 3.6 compatibility for dataclasses
try:
    from dataclasses import dataclass, field, asdict
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

    def asdict(obj):
        """Simple asdict fallback"""
        if hasattr(obj, '__dict__'):
            return {k: v for k, v in obj.__dict__.items() if not k.startswith('_')}
        return obj


@dataclass
class NodeAccess:
    """Represents access information for a single node."""
    hostname: str = None
    ssh_reachable: bool = False
    ssh_user: Optional[str] = None
    ansible_reachable: bool = False
    ansible_host: Optional[str] = None
    ansible_user: Optional[str] = None
    sosreport_path: Optional[str] = None
    preferred_method: Optional[str] = None  # 'ssh', 'ansible', 'sosreport'
    last_checked: Optional[str] = None


@dataclass
class AccessConfig:
    """Configuration for cluster access discovery."""
    ansible_inventory_source: Optional[str] = None
    ansible_inventory_path: Optional[str] = None
    sosreport_directory: Optional[str] = None
    hosts_file: Optional[str] = None
    nodes: Dict[str, dict] = None
    clusters: Dict[str, dict] = None  # cluster_name -> {nodes: [], discovered_from: host}
    discovery_timestamp: Optional[str] = None
    discovery_complete: bool = False

    def __post_init__(self):
        if self.nodes is None:
            self.nodes = {}
        if self.clusters is None:
            self.clusters = {}


class AccessDiscovery:
    """Discovers and validates access methods to cluster nodes."""

    CONFIG_FILE = "cluster_access_config.yaml"
    ANSIBLE_CFG_LOCATIONS = [
        "./ansible.cfg",
        os.path.expanduser("~/.ansible.cfg"),
        "/etc/ansible/ansible.cfg"
    ]
    DEFAULT_ANSIBLE_INVENTORY = "/etc/ansible/hosts"
    SSH_TIMEOUT = 5
    MAX_WORKERS = 10

    def __init__(self, config_dir: str = ".", sosreport_dir: Optional[str] = None,
                 hosts_file: Optional[str] = None, force_rediscover: bool = False,
                 debug: bool = False, ansible_group: Optional[str] = None,
                 skip_ansible: bool = False, cluster_name: Optional[str] = None,
                 local_mode: bool = False):
        self.config_dir = Path(config_dir)
        self.config_path = self.config_dir / self.CONFIG_FILE
        self.sosreport_dir = sosreport_dir
        self.hosts_file = hosts_file
        self.force_rediscover = force_rediscover
        self.debug = debug
        self.ansible_group = ansible_group
        self.skip_ansible = skip_ansible
        self.cluster_name = cluster_name
        self.local_mode = local_mode
        self.local_hostname = None
        self.config = self._load_or_create_config()

    def _load_or_create_config(self) -> AccessConfig:
        """Load existing config or create new one."""
        if self.config_path.exists() and not self.force_rediscover:
            print(f"Loading existing config from {self.config_path}")
            with open(self.config_path, 'r') as f:
                data = yaml.safe_load(f) or {}
                config = AccessConfig(**data)
                # Clear old nodes if hosts file specified (fresh discovery for those hosts)
                if self.hosts_file:
                    if self.debug:
                        print(f"  [DEBUG] Clearing old nodes for fresh cluster discovery")
                    config.nodes = {}
                return config
        if self.force_rediscover:
            print("Starting fresh discovery (--force)")
        return AccessConfig()

    def save_config(self):
        """Save current configuration to YAML file."""
        self.config.discovery_timestamp = datetime.now().isoformat()
        self.config_dir.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            yaml.dump(asdict(self.config), f, default_flow_style=False)
        print(f"Configuration saved to {self.config_path}")

    def discover_ansible_inventory(self) -> Optional[str]:
        """
        Discover Ansible inventory location.
        Priority:
        1. $ANSIBLE_INVENTORY environment variable
        2. ansible.cfg inventory = setting
        3. Default /etc/ansible/hosts
        """
        print("\n=== Discovering Ansible Inventory ===")

        # Check environment variable
        env_inventory = os.environ.get('ANSIBLE_INVENTORY')
        if env_inventory and os.path.exists(env_inventory):
            print(f"Found via $ANSIBLE_INVENTORY: {env_inventory}")
            self.config.ansible_inventory_source = "environment"
            self.config.ansible_inventory_path = env_inventory
            return env_inventory

        # Check ansible.cfg files
        for cfg_path in self.ANSIBLE_CFG_LOCATIONS:
            cfg_path = os.path.expanduser(cfg_path)
            if os.path.exists(cfg_path):
                print(f"Checking {cfg_path}...")
                try:
                    with open(cfg_path, 'r') as f:
                        content = f.read()
                    # Look for inventory = <path> in [defaults] section
                    match = re.search(r'^\s*inventory\s*=\s*(.+?)\s*$', content, re.MULTILINE)
                    if match:
                        inv_path = os.path.expanduser(match.group(1).strip())
                        if os.path.exists(inv_path):
                            print(f"Found via {cfg_path}: {inv_path}")
                            self.config.ansible_inventory_source = cfg_path
                            self.config.ansible_inventory_path = inv_path
                            return inv_path
                except Exception as e:
                    print(f"  Error reading {cfg_path}: {e}")

        # Check default location
        if os.path.exists(self.DEFAULT_ANSIBLE_INVENTORY):
            print(f"Using default: {self.DEFAULT_ANSIBLE_INVENTORY}")
            self.config.ansible_inventory_source = "default"
            self.config.ansible_inventory_path = self.DEFAULT_ANSIBLE_INVENTORY
            return self.DEFAULT_ANSIBLE_INVENTORY

        print("No Ansible inventory found")
        return None

    def get_ansible_hosts(self) -> Dict[str, Dict[str, Any]]:
        """Get hosts from Ansible inventory using ansible-inventory command."""
        print("\n=== Retrieving Ansible Hosts ===")
        hosts = {}

        try:
            cmd = ["ansible-inventory", "--list", "--yaml"]
            if self.config.ansible_inventory_path:
                cmd.extend(["-i", self.config.ansible_inventory_path])

            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)

            if result.returncode == 0:
                inventory = yaml.safe_load(result.stdout)
                hosts = self._parse_ansible_inventory(inventory)
                print(f"Found {len(hosts)} hosts in Ansible inventory")
            else:
                print(f"ansible-inventory failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            print("ansible-inventory timed out")
        except FileNotFoundError:
            print("ansible-inventory command not found")
        except Exception as e:
            print(f"Error getting Ansible hosts: {e}")

        return hosts

    def _parse_ansible_inventory(self, inventory: dict, hosts: dict = None) -> Dict[str, Dict[str, Any]]:
        """Recursively parse Ansible inventory structure."""
        if hosts is None:
            hosts = {}

        if not isinstance(inventory, dict):
            return hosts

        # Parse 'all' group structure
        if 'all' in inventory:
            return self._parse_ansible_inventory(inventory['all'], hosts)

        # Parse hosts at current level
        if 'hosts' in inventory and isinstance(inventory['hosts'], dict):
            for hostname, hostvars in inventory['hosts'].items():
                hosts[hostname] = {
                    'ansible_host': hostvars.get('ansible_host', hostname) if hostvars else hostname,
                    'ansible_user': hostvars.get('ansible_user') if hostvars else None,
                }

        # Recursively parse children groups
        if 'children' in inventory and isinstance(inventory['children'], dict):
            for group_name, group_data in inventory['children'].items():
                self._parse_ansible_inventory(group_data, hosts)

        return hosts

    def get_hosts_from_file(self) -> List[str]:
        """Read hosts from a simple hosts file (one host per line)."""
        hosts = []
        if self.hosts_file and os.path.exists(self.hosts_file):
            print(f"\n=== Reading hosts from {self.hosts_file} ===")
            with open(self.hosts_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        hosts.append(line.split()[0])  # Take first column
            print(f"Found {len(hosts)} hosts")
            self.config.hosts_file = self.hosts_file
        return hosts

    def _extract_sosreport(self, archive_path: str) -> tuple:
        """
        Extract a single SOSreport archive if not already extracted.
        Returns (success: bool, extracted_dir: str or error_msg: str)
        """
        archive_name = os.path.basename(archive_path)
        base_dir = os.path.dirname(archive_path)

        # Determine the expected directory name (remove .tar.xz, .tar.gz, etc.)
        dir_name = archive_name
        for ext in ['.tar.xz', '.tar.gz', '.tar.bz2', '.tgz', '.txz']:
            if dir_name.endswith(ext):
                dir_name = dir_name[:-len(ext)]
                break

        expected_dir = os.path.join(base_dir, dir_name)

        # Check if already extracted
        if os.path.isdir(expected_dir):
            return (True, expected_dir)

        # Determine extraction command based on extension
        if archive_path.endswith('.tar.xz') or archive_path.endswith('.txz'):
            cmd = ['tar', 'xJf', archive_path, '-C', base_dir]
        elif archive_path.endswith('.tar.gz') or archive_path.endswith('.tgz'):
            cmd = ['tar', 'xzf', archive_path, '-C', base_dir]
        elif archive_path.endswith('.tar.bz2'):
            cmd = ['tar', 'xjf', archive_path, '-C', base_dir]
        else:
            return (False, f"Unknown archive format: {archive_name}")

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=300  # 5 minute timeout for large archives
            )
            if result.returncode == 0:
                # Find the extracted directory
                if os.path.isdir(expected_dir):
                    return (True, expected_dir)
                # Sometimes the directory name differs slightly, look for it
                for item in os.listdir(base_dir):
                    item_path = os.path.join(base_dir, item)
                    if os.path.isdir(item_path) and item.startswith('sosreport-') and dir_name.startswith(item[:20]):
                        return (True, item_path)
                return (True, expected_dir)  # Assume it worked
            else:
                return (False, f"Extract failed: {result.stderr[:100]}")
        except subprocess.TimeoutExpired:
            return (False, "Extract timed out (>5 min)")
        except Exception as e:
            return (False, str(e))

    def discover_sosreports(self) -> Dict[str, str]:
        """Discover SOSreport directories and map to hostnames."""
        sosreports = {}
        if not self.sosreport_dir or not os.path.exists(self.sosreport_dir):
            return sosreports

        print(f"\n=== Discovering SOSreports in {self.sosreport_dir} ===")
        self.config.sosreport_directory = self.sosreport_dir

        # First, find and extract any compressed SOSreports (multithreaded)
        archives = []
        archive_extensions = ('.tar.xz', '.tar.gz', '.tar.bz2', '.tgz', '.txz')
        for item in os.listdir(self.sosreport_dir):
            if item.startswith('sosreport-') and item.endswith(archive_extensions):
                archive_path = os.path.join(self.sosreport_dir, item)
                archives.append(archive_path)

        if archives:
            print(f"  Found {len(archives)} compressed SOSreport(s), checking/extracting...")
            with ThreadPoolExecutor(max_workers=min(len(archives), 4)) as executor:
                futures = {executor.submit(self._extract_sosreport, arch): arch for arch in archives}
                for future in as_completed(futures):
                    archive = futures[future]
                    archive_name = os.path.basename(archive)
                    try:
                        success, result = future.result()
                        if success:
                            print(f"    [OK] {archive_name}")
                        else:
                            print(f"    [FAIL] {archive_name}: {result}")
                    except Exception as e:
                        print(f"    [ERROR] {archive_name}: {e}")

        # Look for sosreport directories (pattern: sosreport-<hostname>-<id>)
        for item in os.listdir(self.sosreport_dir):
            item_path = os.path.join(self.sosreport_dir, item)
            if os.path.isdir(item_path) and item.startswith('sosreport-'):
                # Extract hostname from sosreport directory name
                parts = item.split('-')
                if len(parts) >= 2:
                    hostname = parts[1]
                    sosreports[hostname] = item_path
                    print(f"  Found: {hostname} -> {item}")

        # Also check for extracted sosreports by reading etc/hostname
        for item in os.listdir(self.sosreport_dir):
            item_path = os.path.join(self.sosreport_dir, item)
            hostname_file = os.path.join(item_path, 'etc/hostname')
            if os.path.isdir(item_path) and os.path.exists(hostname_file):
                with open(hostname_file, 'r') as f:
                    hostname = f.read().strip().split('.')[0]  # Get short hostname
                if hostname and hostname not in sosreports:
                    sosreports[hostname] = item_path
                    print(f"  Found: {hostname} -> {item}")

        print(f"Found {len(sosreports)} SOSreports")
        return sosreports

    def discover_cluster_name(self, host: str, user: str = None) -> Optional[str]:
        """Discover cluster name from a node."""
        ssh_user = user or 'root'

        # Commands to try for getting cluster name
        name_commands = [
            "crm_attribute -G -n cluster-name -q 2>/dev/null",
            "pcs property show cluster-name 2>/dev/null | grep cluster-name | awk '{print $2}'",
            "corosync-cmapctl totem.cluster_name 2>/dev/null | cut -d= -f2 | tr -d ' '",
            "grep -oP 'cluster_name:\\s*\\K\\S+' /etc/corosync/corosync.conf 2>/dev/null",
        ]

        for cmd in name_commands:
            try:
                ssh_cmd = [
                    "ssh", "-o", "BatchMode=yes",
                    "-o", f"ConnectTimeout={self.SSH_TIMEOUT}",
                    "-o", "StrictHostKeyChecking=no",
                    f"{ssh_user}@{host}",
                    cmd
                ]
                result = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        universal_newlines=True, timeout=self.SSH_TIMEOUT + 2)

                if result.returncode == 0 and result.stdout.strip():
                    cluster_name = result.stdout.strip()
                    if cluster_name and cluster_name != '(null)':
                        return cluster_name
            except Exception:
                continue

        return None

    def get_local_hostname(self) -> str:
        """Get the local hostname (short form)."""
        try:
            result = subprocess.run(
                ['hostname', '-s'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass

        # Fallback to socket
        import socket
        return socket.gethostname().split('.')[0]

    def discover_cluster_nodes_local(self) -> tuple:
        """
        Discover cluster members by running commands locally.
        Returns tuple: (cluster_name, list of cluster node hostnames)
        """
        cluster_nodes = []
        cluster_name = None

        print(f"\n=== Discovering Cluster (local mode) ===")

        # Get local hostname
        self.local_hostname = self.get_local_hostname()
        print(f"  Local hostname: {self.local_hostname}")

        # Get cluster name locally
        name_commands = [
            "crm_attribute -G -n cluster-name -q 2>/dev/null",
            "pcs property show cluster-name 2>/dev/null | grep cluster-name | awk '{print $2}'",
            "corosync-cmapctl totem.cluster_name 2>/dev/null | cut -d= -f2 | tr -d ' '",
            "grep -oP 'cluster_name:\\s*\\K\\S+' /etc/corosync/corosync.conf 2>/dev/null",
        ]

        for cmd in name_commands:
            try:
                result = subprocess.run(
                    cmd, shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    universal_newlines=True, timeout=self.SSH_TIMEOUT
                )
                if result.returncode == 0 and result.stdout.strip():
                    name = result.stdout.strip()
                    if name and name != '(null)':
                        cluster_name = name
                        print(f"  Cluster name: {cluster_name}")
                        break
            except Exception:
                continue

        # Discover cluster nodes locally
        discovery_commands = [
            "crm_node -l | awk '{print $2}'",
            "pcs status nodes | grep -E 'Online|Standby|Offline' | tr ' ' '\\n' | grep -v -E '^$|Online|Standby|Offline|:'",
            "corosync-cmapctl -b nodelist.node | grep 'ring0_addr' | cut -d= -f2 | tr -d ' '",
            "crm status | grep -E '^Node' | awk '{print $2}'",
        ]

        for cmd in discovery_commands:
            try:
                result = subprocess.run(
                    cmd, shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    universal_newlines=True, timeout=self.SSH_TIMEOUT
                )
                if result.returncode == 0 and result.stdout.strip():
                    nodes = [n.strip() for n in result.stdout.strip().split('\n') if n.strip()]
                    if nodes:
                        cluster_nodes = nodes
                        if self.debug:
                            print(f"  [DEBUG] Found cluster nodes via: {cmd[:40]}...")
                        print(f"  Found {len(cluster_nodes)} cluster node(s): {', '.join(cluster_nodes)}")
                        break
            except Exception as e:
                if self.debug:
                    print(f"  [DEBUG] Command failed: {e}")
                continue

        if not cluster_nodes:
            print(f"  Could not discover cluster nodes locally")
            print(f"  Using {self.local_hostname} as only node")
            cluster_nodes = [self.local_hostname]

        # Store cluster info
        if cluster_name:
            self.config.clusters[cluster_name] = {
                'nodes': cluster_nodes,
                'discovered_from': self.local_hostname,
                'discovered_at': datetime.now().isoformat()
            }

        return cluster_name, cluster_nodes

    def discover_cluster_nodes(self, seed_host: str, user: str = None) -> tuple:
        """
        Discover cluster members by connecting to a seed node and querying the cluster.
        Tries multiple methods: crm_node, pcs status, corosync-cmapctl.
        Returns tuple: (cluster_name, list of cluster node hostnames)
        """
        ssh_user = user or 'root'
        cluster_nodes = []
        cluster_name = None

        print(f"\n=== Discovering Cluster from {seed_host} ===")

        # First get cluster name
        cluster_name = self.discover_cluster_name(seed_host, ssh_user)
        if cluster_name:
            print(f"  Cluster name: {cluster_name}")
        else:
            if self.debug:
                print(f"  [DEBUG] Could not determine cluster name")

        # Commands to try for discovering cluster nodes
        discovery_commands = [
            # crm_node (SUSE/generic)
            "crm_node -l | awk '{print $2}'",
            # pcs status (RHEL)
            "pcs status nodes | grep -E 'Online|Standby|Offline' | tr ' ' '\\n' | grep -v -E '^$|Online|Standby|Offline|:'",
            # corosync-cmapctl
            "corosync-cmapctl -b nodelist.node | grep 'ring0_addr' | cut -d= -f2 | tr -d ' '",
            # crm status (fallback)
            "crm status | grep -E '^Node' | awk '{print $2}'",
        ]

        for cmd in discovery_commands:
            try:
                ssh_cmd = [
                    "ssh", "-o", "BatchMode=yes",
                    "-o", f"ConnectTimeout={self.SSH_TIMEOUT}",
                    "-o", "StrictHostKeyChecking=no",
                    f"{ssh_user}@{seed_host}",
                    cmd
                ]
                result = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        universal_newlines=True, timeout=self.SSH_TIMEOUT + 2)

                if result.returncode == 0 and result.stdout.strip():
                    nodes = [n.strip() for n in result.stdout.strip().split('\n') if n.strip()]
                    if nodes:
                        cluster_nodes = nodes
                        if self.debug:
                            print(f"  [DEBUG] Found cluster nodes via: {cmd[:40]}...")
                        print(f"  Found {len(cluster_nodes)} cluster node(s): {', '.join(cluster_nodes)}")
                        break
            except subprocess.TimeoutExpired:
                continue
            except Exception as e:
                if self.debug:
                    print(f"  [DEBUG] Command failed: {e}")
                continue

        if not cluster_nodes:
            print(f"  Could not discover cluster nodes from {seed_host}")
            print(f"  Using {seed_host} as only node")
            cluster_nodes = [seed_host]

        # Store cluster info
        if cluster_name:
            self.config.clusters[cluster_name] = {
                'nodes': cluster_nodes,
                'discovered_from': seed_host,
                'discovered_at': datetime.now().isoformat()
            }

        return cluster_name, cluster_nodes

    def check_ssh_access(self, hostname: str, user: str = None) -> tuple:
        """Check SSH access to a host. Returns (reachable, user)."""
        users_to_try = [user] if user else [os.environ.get('USER', 'root'), 'root']

        for try_user in users_to_try:
            if try_user is None:
                continue
            try:
                cmd = [
                    "ssh", "-o", "BatchMode=yes",
                    "-o", f"ConnectTimeout={self.SSH_TIMEOUT}",
                    "-o", "StrictHostKeyChecking=no",
                    f"{try_user}@{hostname}",
                    "echo ok"
                ]
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=self.SSH_TIMEOUT + 2)
                if result.returncode == 0 and "ok" in result.stdout:
                    return True, try_user
                elif self.debug:
                    print(f"    [DEBUG] SSH {try_user}@{hostname} failed: {result.stderr.strip()[:60]}")
            except subprocess.TimeoutExpired:
                if self.debug:
                    print(f"    [DEBUG] SSH {try_user}@{hostname} timed out")
            except Exception as e:
                if self.debug:
                    print(f"    [DEBUG] SSH {try_user}@{hostname} error: {e}")

        return False, None

    def check_ansible_access(self, hostname: str, ansible_host: str = None,
                            ansible_user: str = None) -> bool:
        """Check Ansible access to a host using ansible ping."""
        try:
            cmd = ["ansible", hostname, "-m", "ping", "-o"]
            if self.config.ansible_inventory_path:
                cmd.extend(["-i", self.config.ansible_inventory_path])

            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=15)
            return "SUCCESS" in result.stdout
        except Exception:
            return False

    def check_node_access(self, hostname: str, ansible_info: dict = None,
                         sosreport_path: str = None) -> NodeAccess:
        """Check all access methods for a single node (thread-safe)."""
        node = NodeAccess(hostname=hostname)
        node.last_checked = datetime.now().isoformat()

        # Check SSH access (preferred)
        ssh_user = ansible_info.get('ansible_user') if ansible_info else None
        ssh_host = ansible_info.get('ansible_host', hostname) if ansible_info else hostname
        node.ssh_reachable, node.ssh_user = self.check_ssh_access(ssh_host, ssh_user)

        # Check Ansible access
        if ansible_info:
            node.ansible_host = ansible_info.get('ansible_host')
            node.ansible_user = ansible_info.get('ansible_user')
            if not node.ssh_reachable:  # Only check Ansible if SSH failed
                node.ansible_reachable = self.check_ansible_access(hostname,
                    node.ansible_host, node.ansible_user)

        # Record SOSreport path
        if sosreport_path:
            node.sosreport_path = sosreport_path

        # Determine preferred access method
        if node.ssh_reachable:
            node.preferred_method = 'ssh'
        elif node.ansible_reachable:
            node.preferred_method = 'ansible'
        elif node.sosreport_path:
            node.preferred_method = 'sosreport'

        return node

    def discover_all(self) -> AccessConfig:
        """
        Main discovery routine - discovers all access methods using multithreading.
        """
        print("=" * 60)
        print("SAP Pacemaker Cluster - Access Discovery")
        print("=" * 60)

        # Handle local mode - running on the cluster node itself
        if self.local_mode:
            return self._discover_local_mode()

        # Collect all hosts from different sources
        all_hosts = {}  # hostname -> {ansible_info, sosreport_path}
        file_hosts = []

        # 0. If SOSreport directory specified, discover SOSreports FIRST and use ONLY those nodes
        if self.sosreport_dir:
            sosreports = self.discover_sosreports()
            if sosreports:
                print(f"\n[INFO] SOSreport mode: analyzing only nodes with SOSreports")
                # Clear old nodes - only analyze SOSreport nodes
                self.config.nodes = {}
                for hostname, path in sosreports.items():
                    all_hosts[hostname] = {'ansible_info': None, 'sosreport_path': path}
                # Skip all other discovery - go straight to access check
                print(f"\n=== Checking access to {len(all_hosts)} SOSreport nodes ===")
                for hostname, info in all_hosts.items():
                    node = self.check_node_access(hostname, None, info.get('sosreport_path'))
                    self.config.nodes[hostname] = asdict(node)
                    print(f"  {hostname}: SOSreport -> {node.preferred_method or 'none'}")
                self.config.sosreport_directory = self.sosreport_dir
                self.config.discovery_complete = True
                self.save_config()
                self._print_summary()
                return self.config

        # 1. Check if cluster name specified - use saved cluster nodes
        if self.cluster_name:
            if self.cluster_name in self.config.clusters:
                cluster_info = self.config.clusters[self.cluster_name]
                file_hosts = cluster_info.get('nodes', [])
                print(f"\n=== Using saved cluster: {self.cluster_name} ===")
                print(f"  Nodes: {', '.join(file_hosts)}")
                print(f"  Discovered from: {cluster_info.get('discovered_from', 'unknown')}")
                # Clear old nodes - only check this cluster's nodes
                self.config.nodes = {}
            else:
                print(f"\n[WARNING] Cluster '{self.cluster_name}' not found in config")
                print(f"  Known clusters: {', '.join(self.config.clusters.keys()) or '(none)'}")
                print(f"  Run with a node name first to discover the cluster")

        # 2. Get hosts from file/command line
        if not file_hosts:
            file_hosts = self.get_hosts_from_file()
            if file_hosts:
                # Hosts specified on command line - clear old nodes, only check these
                print(f"\n[INFO] Host mode: analyzing only specified hosts")
                self.config.nodes = {}

        # 3. If hosts specified, try to discover cluster members from first reachable host
        if file_hosts and not self.cluster_name:
            if self.debug:
                print(f"  [DEBUG] Hosts specified, attempting cluster auto-discovery")

            # Try to discover cluster nodes from the first specified host
            for seed_host in file_hosts:
                # Quick SSH check
                reachable, ssh_user = self.check_ssh_access(seed_host)
                if reachable:
                    # Discover cluster members (returns cluster_name, nodes)
                    discovered_name, cluster_nodes = self.discover_cluster_nodes(seed_host, ssh_user)
                    # Use cluster nodes instead of just the specified hosts
                    file_hosts = cluster_nodes
                    break
                else:
                    if self.debug:
                        print(f"  [DEBUG] {seed_host} not reachable, trying next...")

        # 3. Discover Ansible inventory (skip if hosts provided)
        if not self.skip_ansible and not file_hosts:
            self.discover_ansible_inventory()
            ansible_hosts = self.get_ansible_hosts()

            # Filter by group if specified
            if self.ansible_group:
                filtered_hosts = {}
                for hostname, info in ansible_hosts.items():
                    groups = info.get('groups', [])
                    if self.ansible_group in groups or self.ansible_group == 'all':
                        filtered_hosts[hostname] = info
                if self.debug:
                    print(f"  [DEBUG] Filtered to group '{self.ansible_group}': {len(filtered_hosts)} hosts")
                ansible_hosts = filtered_hosts

            for hostname, info in ansible_hosts.items():
                all_hosts[hostname] = {'ansible_info': info, 'sosreport_path': None}

        # 4. Add hosts from file/cluster discovery
        for hostname in file_hosts:
            if hostname not in all_hosts:
                all_hosts[hostname] = {'ansible_info': None, 'sosreport_path': None}

        # 3. Discover SOSreports
        sosreports = self.discover_sosreports()
        for hostname, path in sosreports.items():
            if hostname in all_hosts:
                all_hosts[hostname]['sosreport_path'] = path
            else:
                all_hosts[hostname] = {'ansible_info': None, 'sosreport_path': path}

        if not all_hosts:
            print("\nNo hosts discovered. Please provide:")
            print("  - Ansible inventory (ansible.cfg or $ANSIBLE_INVENTORY)")
            print("  - Hosts file (--hosts-file)")
            print("  - SOSreport directory (--sosreport-dir)")
            return self.config

        # 4. Check access to all hosts using thread pool
        print(f"\n=== Checking access to {len(all_hosts)} hosts (multithreaded) ===")

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            futures = {}
            for hostname, info in all_hosts.items():
                future = executor.submit(
                    self.check_node_access,
                    hostname,
                    info.get('ansible_info'),
                    info.get('sosreport_path')
                )
                futures[future] = hostname

            for future in as_completed(futures):
                hostname = futures[future]
                try:
                    node = future.result()
                    self.config.nodes[hostname] = asdict(node)
                    status = []
                    if node.ssh_reachable:
                        status.append(f"SSH({node.ssh_user})")
                    if node.ansible_reachable:
                        status.append("Ansible")
                    if node.sosreport_path:
                        status.append("SOSreport")
                    print(f"  {hostname}: {', '.join(status) if status else 'NO ACCESS'} "
                          f"-> {node.preferred_method or 'none'}")
                except Exception as e:
                    print(f"  {hostname}: Error - {e}")

        self.config.discovery_complete = True
        self.save_config()

        # Print summary
        self._print_summary()

        return self.config

    def _discover_local_mode(self) -> AccessConfig:
        """
        Discovery routine for local mode - running on the cluster node itself.
        The local node uses direct command execution, other nodes use SSH.
        """
        print("\n[INFO] Local mode: running on cluster node")

        # Clear old nodes for fresh discovery
        self.config.nodes = {}

        # Discover cluster nodes locally
        cluster_name, cluster_nodes = self.discover_cluster_nodes_local()

        if not cluster_nodes:
            print("[ERROR] Could not discover any cluster nodes")
            return self.config

        # Get local hostname
        local_hostname = self.local_hostname or self.get_local_hostname()

        print(f"\n=== Checking access to {len(cluster_nodes)} cluster node(s) ===")

        # Process each node
        for node_name in cluster_nodes:
            if node_name == local_hostname:
                # Local node - use local execution
                node = NodeAccess(hostname=node_name)
                node.last_checked = datetime.now().isoformat()
                node.preferred_method = 'local'
                self.config.nodes[node_name] = asdict(node)
                print(f"  {node_name}: LOCAL (this node)")
            else:
                # Remote node - check SSH access
                node = self.check_node_access(node_name, None, None)
                self.config.nodes[node_name] = asdict(node)
                status = []
                if node.ssh_reachable:
                    status.append(f"SSH({node.ssh_user})")
                print(f"  {node_name}: {', '.join(status) if status else 'NO ACCESS'} "
                      f"-> {node.preferred_method or 'none'}")

        self.config.discovery_complete = True
        self.save_config()

        # Print summary
        self._print_summary()

        return self.config

    def _print_summary(self):
        """Print discovery summary."""
        print("\n" + "=" * 60)
        print("Discovery Summary")
        print("=" * 60)

        total = len(self.config.nodes)
        local_count = sum(1 for n in self.config.nodes.values() if n.get('preferred_method') == 'local')
        ssh_count = sum(1 for n in self.config.nodes.values() if n.get('ssh_reachable'))
        ansible_count = sum(1 for n in self.config.nodes.values() if n.get('ansible_reachable'))
        sos_count = sum(1 for n in self.config.nodes.values() if n.get('sosreport_path'))
        no_access = sum(1 for n in self.config.nodes.values() if not n.get('preferred_method'))

        print(f"Total nodes:      {total}")
        if local_count > 0:
            print(f"Local (this node):{local_count}")
        print(f"SSH accessible:   {ssh_count}")
        print(f"Ansible access:   {ansible_count}")
        print(f"SOSreport avail:  {sos_count}")
        print(f"No access:        {no_access}")
        print(f"\nConfig saved to: {self.config_path}")

        if self.config.ansible_inventory_path:
            print(f"Ansible inventory: {self.config.ansible_inventory_path}")
            print(f"  (source: {self.config.ansible_inventory_source})")


def show_config(config_path: Path):
    """Display the current configuration in a user-friendly format."""
    if not config_path.exists():
        print(f"No configuration file found at {config_path}")
        print("\nRun discovery first:")
        print("  ./cluster_health_check.py hana01")
        return False

    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    print("\n" + "=" * 60)
    print(" SAP Cluster Health Check - Configuration")
    print("=" * 60)
    print(f"Config file: {config_path}")

    # Show clusters prominently
    clusters = config.get('clusters', {})
    if clusters:
        print("\n--- Discovered Clusters ---")
        for name, info in clusters.items():
            nodes = info.get('nodes', [])
            discovered_from = info.get('discovered_from', 'unknown')
            print(f"\n  Cluster: {name}")
            print(f"    Nodes: {', '.join(nodes)}")
            print(f"    Discovered from: {discovered_from}")
            print(f"\n    To check this cluster:")
            print(f"      ./cluster_health_check.py -C {name}")
    else:
        print("\n[INFO] No clusters discovered yet")
        print("  Run: ./cluster_health_check.py hana01")

    # Show node summary
    nodes = config.get('nodes', {})
    if nodes:
        print(f"\n--- All Discovered Nodes ({len(nodes)}) ---")
        accessible = [n for n, info in nodes.items() if info.get('preferred_method')]
        no_access = [n for n, info in nodes.items() if not info.get('preferred_method')]

        if accessible:
            print(f"\n  Accessible ({len(accessible)}):")
            for name in sorted(accessible)[:10]:  # Show first 10
                info = nodes[name]
                method = info.get('preferred_method', 'none')
                print(f"    {name}: {method}")
            if len(accessible) > 10:
                print(f"    ... and {len(accessible) - 10} more")

        if no_access:
            print(f"\n  No access ({len(no_access)}): {', '.join(sorted(no_access)[:5])}", end='')
            if len(no_access) > 5:
                print(f" ... and {len(no_access) - 5} more")
            else:
                print()

    # Show other config
    if config.get('sosreport_directory'):
        print(f"\n--- SOSreport Directory ---")
        print(f"  {config['sosreport_directory']}")

    if config.get('ansible_inventory_path'):
        print(f"\n--- Ansible Inventory ---")
        print(f"  Path: {config['ansible_inventory_path']}")
        print(f"  Source: {config.get('ansible_inventory_source', 'unknown')}")

    print("\n--- Quick Commands ---")
    if clusters:
        first_cluster = list(clusters.keys())[0]
        print(f"  Check cluster:    ./cluster_health_check.py -C {first_cluster}")
    print("  Force rediscover: ./cluster_health_check.py -f hana01")
    print("  Delete config:    ./cluster_health_check.py -D")
    print("  Show guide:       ./cluster_health_check.py --guide")

    return True


def delete_config(config_path: Path):
    """Delete the configuration file to restart investigation."""
    if not config_path.exists():
        print(f"No configuration file found at {config_path}")
        return False

    try:
        os.remove(config_path)
        print(f"Configuration file deleted: {config_path}")
        print("Run discovery again to start a fresh investigation.")
        return True
    except Exception as e:
        print(f"Error deleting configuration: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Discover access methods to SAP Pacemaker cluster nodes'
    )
    parser.add_argument(
        '--config-dir', '-c',
        default='.',
        help='Directory to store configuration (default: current directory)'
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
        '--force', '-f',
        action='store_true',
        help='Force rediscovery (ignore existing config)'
    )
    parser.add_argument(
        '--workers', '-w',
        type=int,
        default=10,
        help='Number of parallel workers (default: 10)'
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

    args = parser.parse_args()

    config_path = Path(args.config_dir) / AccessDiscovery.CONFIG_FILE

    # Handle show-config action
    if args.show_config:
        show_config(config_path)
        sys.exit(0)

    # Handle delete-config action
    if args.delete_config:
        delete_config(config_path)
        sys.exit(0)

    discovery = AccessDiscovery(
        config_dir=args.config_dir,
        sosreport_dir=args.sosreport_dir,
        hosts_file=args.hosts_file,
        force_rediscover=args.force
    )
    discovery.MAX_WORKERS = args.workers

    try:
        discovery.discover_all()
        # Show the saved config at the end
        print("\n" + "-" * 60)
        print("Saved Configuration:")
        print("-" * 60)
        show_config(config_path)
    except KeyboardInterrupt:
        print("\nDiscovery interrupted. Saving partial results...")
        discovery.save_config()
        sys.exit(1)


if __name__ == '__main__':
    main()
