# SAP HANA Pacemaker Cluster Health Check

A comprehensive health check tool for SAP HANA Pacemaker clusters on RHEL and SUSE Linux Enterprise.

## Features

- **Multiple Access Methods**: SSH, Ansible inventory, or SOSreport analysis
- **Multithreaded Execution**: Parallel node connectivity checks and rule execution
- **19 Built-in Health Checks**: Covering cluster configuration, Pacemaker/Corosync, and SAP-specific validations
- **Incremental Investigation**: YAML-based configuration persists between runs
- **Detailed Reporting**: YAML reports with timestamps for audit trails

## Installation

```bash
git clone https://github.com/mmoster/sap_hana_healthcheck.git
cd sap_hana_healthcheck
```

Requirements:
- Python 3.8+
- PyYAML (`pip install pyyaml`)
- For live checks: SSH access or Ansible configured
- For offline analysis: SOSreport directories

## Specifying Target Nodes

**Important**: By default, the tool auto-discovers hosts from Ansible inventory. On an Ansible master server with hundreds of hosts, this may include many systems that are not part of your SAP cluster. You should explicitly specify your target nodes using one of the methods below.

### Method 1: Custom Hosts File (Recommended)

Create a simple text file containing only your SAP cluster nodes (one hostname per line):

```bash
# Create hosts file with your cluster nodes
cat > my_cluster.txt << EOF
hana01
hana02
hana03
EOF

# Run health check with custom hosts file
cd wrapper
./cluster_health_check.py --hosts-file my_cluster.txt
```

This completely bypasses Ansible inventory discovery and only checks the specified nodes.

### Method 2: Deploy with Explicit Hosts

When using the deploy script, specify hosts directly on the command line:

```bash
# Deploy with specific hosts - only these will be checked
./deploy.sh /opt/sap_cluster_check hana01 hana02

# The hosts are written to hosts.txt in the target directory
cd /opt/sap_cluster_check
./run_discovery.sh
```

### Method 3: Edit hosts.txt After Deployment

Deploy first, then manually edit the hosts file:

```bash
# Deploy without hosts
./deploy.sh /opt/sap_cluster_check

# Edit hosts.txt to add your nodes
cat > /opt/sap_cluster_check/hosts.txt << EOF
hana01
hana02
EOF

# Run discovery
cd /opt/sap_cluster_check
./run_discovery.sh
```

### Method 4: Environment Variable

Set the `ANSIBLE_INVENTORY` environment variable to point to a custom inventory file containing only your cluster nodes:

```bash
export ANSIBLE_INVENTORY=/path/to/my_sap_cluster_inventory
cd wrapper
./cluster_health_check.py
```

### Method 5: Single Host Discovery

To check only a single host (useful for testing):

```bash
cd /opt/sap_cluster_check
./run_discovery.sh --host hana01
```

### Hosts File Format

The hosts file is a simple text file with one hostname or IP address per line:

```
# Comments start with #
hana01.example.com
hana02.example.com
192.168.1.100

# Empty lines are ignored
hana03
```

### Verifying Your Configuration

Before running the full health check, verify which nodes will be discovered:

```bash
# Show current configuration
cd wrapper
./cluster_health_check.py --show-config

# Run only access discovery to test connectivity
./cluster_health_check.py --access-only

# Force rediscovery if you changed the hosts file
./cluster_health_check.py --force --access-only
```

## Quick Start

### Option 1: Deploy Discovery Tool (empfohlen für Tests)

```bash
# Deploy in ein beliebiges Verzeichnis
./deploy.sh /pfad/zum/ziel hana01 hana02

# Oder ohne Hosts (später in hosts.txt eintragen)
./deploy.sh /tmp/my_discovery

# Im Zielverzeichnis arbeiten
cd /tmp/my_discovery
./run_discovery.sh --list-rules
./run_discovery.sh
```

### Option 2: Full Health Check

```bash
cd wrapper

# Run full health check (auto-discovers Ansible inventory)
./cluster_health_check.py

# Access discovery only
./cluster_health_check.py --access-only

# Use custom hosts file
./cluster_health_check.py --hosts-file /path/to/hosts.txt

# Analyze SOSreports offline
./cluster_health_check.py --sosreport-dir /path/to/sosreports/

# List available health checks
./cluster_health_check.py --list-rules
```

## Usage

```
usage: cluster_health_check.py [-h] [--hosts-file HOSTS_FILE]
                               [--sosreport-dir SOSREPORT_DIR]
                               [--config-dir CONFIG_DIR] [--access-only]
                               [--show-config] [--delete-config] [--force]
                               [--workers WORKERS] [--rules-path RULES_PATH]
                               [--list-rules]
                               [--skip {access,config,pacemaker,sap,report} ...]

Options:
  -H, --hosts-file      File containing list of hosts (one per line)
  -s, --sosreport-dir   Directory containing SOSreport archives/directories
  -c, --config-dir      Directory to store configuration
  -a, --access-only     Only run access discovery step
  -S, --show-config     Display current configuration and exit
  -D, --delete-config   Delete configuration file to restart investigation
  -f, --force           Force rediscovery (ignore existing config)
  -w, --workers         Number of parallel workers (default: 10)
  -r, --rules-path      Path to CHK_*.yaml rules directory
  -L, --list-rules      List available health check rules and exit
  --skip                Skip specific steps (access, config, pacemaker, sap, report)
```

## Health Check Steps

| Step | Description |
|------|-------------|
| 1. Access Discovery | Discovers SSH/Ansible/SOSreport access to cluster nodes |
| 2. Cluster Configuration | Node status, quorum, clone config, package consistency |
| 3. Pacemaker/Corosync | STONITH, resources, fencing, master/slave roles |
| 4. SAP-Specific | HANA SR status, replication mode, HA/DR hooks, systemd |
| 5. Report Generation | Summary and detailed YAML report |

## Included Health Checks (19 Rules)

### Cluster Configuration
| Check ID | Severity | Description |
|----------|----------|-------------|
| CHK_NODE_STATUS | CRITICAL | Verify all cluster nodes are online |
| CHK_CLUSTER_QUORUM | CRITICAL | Verify cluster has quorum |
| CHK_QUORUM_CONFIG | CRITICAL | Validate quorum configuration |
| CHK_CLONE_CONFIG | CRITICAL | Validate clone resource configuration |
| CHK_SETUP_VALIDATION | CRITICAL | Validate against SAP HANA HA best practices |
| CHK_CIB_TIME_SYNC | WARNING | Verify CIB updates are synchronized |
| CHK_PACKAGE_CONSISTENCY | CRITICAL | Verify package versions across nodes |

### Pacemaker/Corosync
| Check ID | Severity | Description |
|----------|----------|-------------|
| CHK_STONITH_CONFIG | CRITICAL | Verify STONITH/fencing is enabled |
| CHK_RESOURCE_STATUS | CRITICAL | Verify SAP HANA resources are running |
| CHK_RESOURCE_FAILURES | WARNING | Detect failed resource operations |
| CHK_ALERT_FENCING | WARNING | Validate SAPHanaSR-alert-fencing |
| CHK_MASTER_SLAVE_ROLES | CRITICAL | Verify master/slave role consistency |
| CHK_MAJORITY_MAKER | CRITICAL | Validate majority maker constraints |

### SAP-Specific
| Check ID | Severity | Description |
|----------|----------|-------------|
| CHK_HANA_SR_STATUS | CRITICAL | Verify HANA System Replication status |
| CHK_REPLICATION_MODE | WARNING | Verify replication mode is synchronous |
| CHK_HADR_HOOKS | CRITICAL | Validate HA/DR provider hooks |
| CHK_HANA_AUTOSTART | WARNING | Validate HANA autostart is disabled |
| CHK_SYSTEMD_SAP | WARNING | Validate SAP Host Agent and systemd |
| CHK_SITE_ROLES | CRITICAL | Verify site roles consistency |

## Access Discovery

The tool automatically discovers cluster nodes from multiple sources:

1. **Ansible Inventory** (checked in order):
   - `$ANSIBLE_INVENTORY` environment variable
   - `./ansible.cfg` → `inventory =` setting
   - `~/.ansible.cfg` → `inventory =` setting
   - `/etc/ansible/ansible.cfg` → `inventory =` setting
   - `/etc/ansible/hosts` (default)

2. **Hosts File**: Simple text file with one hostname per line

3. **SOSreport**: Extracts hostnames from sosreport directories

## Configuration

Results are stored in `cluster_access_config.yaml`:

```yaml
ansible_inventory_source: default
ansible_inventory_path: /etc/ansible/hosts
nodes:
  node1.example.com:
    hostname: node1.example.com
    ssh_reachable: true
    ssh_user: root
    preferred_method: ssh
  node2.example.com:
    hostname: node2.example.com
    ansible_reachable: true
    preferred_method: ansible
```

Delete this file (`--delete-config`) to restart the investigation from scratch.

## Output

Reports are saved as YAML files with timestamps:

```
health_check_report_20260305_113455.yaml
```

Example output:
```
===============================================================
 STEP 5: Health Check Report
===============================================================

  Total Checks Run:    19
  Passed:              15
  Failed:              3
    - Critical:        1
    - Warning:         2
  Skipped:             1
  Errors:              0

  CRITICAL FAILURES:
    [CRIT] CHK_STONITH_CONFIG (node1)
           No STONITH resources configured - split-brain risk!
```

## Standalone Discovery Framework

Das Discovery-Framework ermöglicht das Sammeln von Systeminformationen via SSH basierend auf YAML-Regeln.

### Deployment

```bash
# Deploy mit Hosts
./deploy.sh /opt/cluster_discovery hana01 hana02 hana03

# Deploy ohne Hosts
./deploy.sh /tmp/discovery
echo "hana04" >> /tmp/discovery/hosts.txt
```

### Verwendung

```bash
cd /opt/cluster_discovery

# Verfügbare Regeln anzeigen
./run_discovery.sh --list-rules

# Alle Discoveries ausführen
./run_discovery.sh

# Nur bestimmte Gruppen
./run_discovery.sh --groups system_info network

# Nur bestimmten Host
./run_discovery.sh --host hana01

# Ergebnisse direkt anzeigen
./run_discovery.sh --show-data
```

### Discovery-Gruppen

| Gruppe | Beschreibung |
|--------|--------------|
| `system_info` | Hostname, OS, Kernel, Uptime, Architektur |
| `cluster_basics` | Pacemaker/Corosync Version, Cluster-Name, Nodes, Quorum |
| `sap_hana` | SID, Instanz, Version, SR-Status, Topologie |
| `resources` | Cluster-Ressourcen, STONITH, Constraints |
| `network` | Corosync-Ringe, IPs, /etc/hosts, Firewall |

### Eigene Discovery-Regeln erstellen

Neue YAML-Datei in `discovery_rules/` erstellen:

```yaml
group: storage
description: Storage-Informationen
enabled: true

discoveries:
  - id: DISC_DISK_USAGE
    description: Festplattennutzung
    live_cmd: "df -h"
    parser:
      type: lines
    store_as: disk_usage

  - id: DISC_MOUNTS
    description: Gemountete Filesysteme
    live_cmd: "mount | grep -E '^/dev'"
    parser:
      type: lines
    store_as: mounts
```

### Parser-Typen

| Typ | Beschreibung |
|-----|--------------|
| `raw` | Ausgabe als String |
| `lines` | Ausgabe als Liste von Zeilen |
| `key_value` | Key=Value Paare als Dictionary |
| `regex` | Regex-Patterns extrahieren |

## Project Structure

```
sap_hana_healthcheck/
├── README.md
├── deploy.sh                       # Deployment-Script
├── .gitignore
├── wrapper/
│   ├── cluster_health_check.py     # Main entry point
│   ├── cluster_access_config.yaml  # Generated config
│   ├── access/
│   │   └── discover_access.py      # Access discovery module
│   └── rules/
│       ├── __init__.py
│       └── engine.py               # Rules engine
└── tests/
    └── hana04_discovery/
        ├── discovery_runner.py     # Standalone discovery runner
        ├── run_discovery.sh        # Wrapper script
        ├── hosts.txt               # Target hosts
        └── discovery_rules/        # YAML rule definitions
            ├── 00_system_info.yaml
            ├── 01_cluster_basics.yaml
            ├── 02_sap_hana.yaml
            ├── 03_resources.yaml
            └── 04_network.yaml
```

## License

MIT License

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
