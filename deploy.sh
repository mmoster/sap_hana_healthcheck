#!/bin/bash
#
# SAP Cluster Discovery Tool - Deploy Script
#
# Erstellt ein eigenständiges Discovery-Paket in einem Zielverzeichnis.
#
# Verwendung:
#   ./deploy.sh <ZIELVERZEICHNIS> [HOSTS...]
#
# Beispiele:
#   ./deploy.sh /tmp/cluster_check hana04
#   ./deploy.sh ~/discovery hana01 hana02 hana03
#   ./deploy.sh /opt/sap_discovery   # hosts.txt manuell bearbeiten
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${1:-}"
shift 2>/dev/null || true
HOSTS=("$@")

# Farben (falls Terminal unterstützt)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

print_banner() {
    echo ""
    echo "=============================================="
    echo " SAP Cluster Discovery Tool - Deploy"
    echo "=============================================="
    echo ""
}

show_usage() {
    echo "Verwendung: $0 <ZIELVERZEICHNIS> [HOSTS...]"
    echo ""
    echo "Argumente:"
    echo "  ZIELVERZEICHNIS   Verzeichnis für das Discovery-Tool"
    echo "  HOSTS             Optional: Hosts für hosts.txt"
    echo ""
    echo "Beispiele:"
    echo "  $0 /tmp/cluster_check hana04"
    echo "  $0 ~/discovery hana01 hana02"
    echo "  $0 /opt/sap_discovery"
    echo ""
}

check_dependencies() {
    log_info "Prüfe Abhängigkeiten..."

    local missing=0

    # Python3
    if command -v python3 &> /dev/null; then
        echo "  [OK] python3: $(python3 --version 2>&1)"
    else
        echo "  [FEHLT] python3"
        missing=1
    fi

    # PyYAML
    if python3 -c "import yaml" 2>/dev/null; then
        echo "  [OK] python3-yaml"
    else
        echo "  [FEHLT] python3-yaml (PyYAML)"
        missing=1
    fi

    # SSH
    if command -v ssh &> /dev/null; then
        echo "  [OK] ssh"
    else
        echo "  [FEHLT] ssh"
        missing=1
    fi

    if [ $missing -eq 1 ]; then
        echo ""
        log_warn "Fehlende Pakete installieren:"
        echo ""
        echo "  RHEL/CentOS/Fedora:"
        echo "    sudo dnf install python3 python3-pyyaml openssh-clients"
        echo ""
        echo "  SUSE/SLES:"
        echo "    sudo zypper install python3 python3-PyYAML openssh"
        echo ""
        echo "  Ubuntu/Debian:"
        echo "    sudo apt install python3 python3-yaml openssh-client"
        echo ""
        return 1
    fi

    return 0
}

deploy_files() {
    log_info "Erstelle Verzeichnisstruktur..."
    mkdir -p "$TARGET_DIR/discovery_rules"

    log_info "Kopiere Dateien..."

    # Hauptskripte
    cp "$SCRIPT_DIR/tests/hana04_discovery/discovery_runner.py" "$TARGET_DIR/"
    cp "$SCRIPT_DIR/tests/hana04_discovery/run_discovery.sh" "$TARGET_DIR/"
    cp "$SCRIPT_DIR/wrapper/access/discover_access.py" "$TARGET_DIR/"

    # Discovery-Regeln
    cp "$SCRIPT_DIR/tests/hana04_discovery/discovery_rules/"*.yaml "$TARGET_DIR/discovery_rules/"

    # Ausführbar machen
    chmod +x "$TARGET_DIR/discovery_runner.py"
    chmod +x "$TARGET_DIR/run_discovery.sh"

    echo "  [OK] discovery_runner.py"
    echo "  [OK] discover_access.py"
    echo "  [OK] run_discovery.sh"
    echo "  [OK] discovery_rules/*.yaml"
}

create_hosts_file() {
    log_info "Erstelle hosts.txt..."

    if [ ${#HOSTS[@]} -gt 0 ]; then
        # Hosts aus Argumenten
        echo "# Hosts für Discovery" > "$TARGET_DIR/hosts.txt"
        for host in "${HOSTS[@]}"; do
            echo "$host" >> "$TARGET_DIR/hosts.txt"
        done
        echo "  [OK] ${#HOSTS[@]} Host(s) eingetragen: ${HOSTS[*]}"
    else
        # Leere Template-Datei
        cat > "$TARGET_DIR/hosts.txt" << 'EOF'
# Hosts für Discovery - einen Host pro Zeile
# Zeilen mit # werden ignoriert
#
# Beispiel:
# hana01
# hana02
# hana03
EOF
        echo "  [OK] Template erstellt (bitte anpassen!)"
    fi
}

fix_imports() {
    log_info "Passe Imports an..."

    # discovery_runner.py: Import-Pfad anpassen für standalone
    sed -i 's|WRAPPER_DIR = SCRIPT_DIR.parent.parent / "wrapper"|WRAPPER_DIR = SCRIPT_DIR|' \
        "$TARGET_DIR/discovery_runner.py"

    # Entferne den sys.path.insert für access-Unterverzeichnis
    sed -i 's|sys.path.insert(0, str(WRAPPER_DIR / "access"))|# Standalone mode - discover_access.py im gleichen Verzeichnis|' \
        "$TARGET_DIR/discovery_runner.py"

    echo "  [OK] Imports angepasst für Standalone-Betrieb"
}

print_summary() {
    echo ""
    echo "=============================================="
    echo " Deployment abgeschlossen"
    echo "=============================================="
    echo ""
    echo "Verzeichnis: $TARGET_DIR"
    echo ""
    echo "Dateien:"
    ls -la "$TARGET_DIR/" | grep -v "^total" | awk '{print "  " $0}'
    echo ""
    echo "Discovery-Regeln:"
    ls "$TARGET_DIR/discovery_rules/" | awk '{print "  - " $0}'
    echo ""
    echo "----------------------------------------------"
    echo " Nächste Schritte:"
    echo "----------------------------------------------"
    echo ""
    echo "  1. Ins Verzeichnis wechseln:"
    echo "     cd $TARGET_DIR"
    echo ""
    if [ ${#HOSTS[@]} -eq 0 ]; then
        echo "  2. Hosts eintragen:"
        echo "     echo 'hana04' >> hosts.txt"
        echo ""
        echo "  3. Verfügbare Regeln anzeigen:"
    else
        echo "  2. Verfügbare Regeln anzeigen:"
    fi
    echo "     ./run_discovery.sh --list-rules"
    echo ""
    echo "  3. Discovery starten:"
    echo "     ./run_discovery.sh"
    echo ""
    echo "  4. Nur bestimmte Gruppen:"
    echo "     ./run_discovery.sh --groups system_info network"
    echo ""
    echo "  5. Ergebnisse anzeigen:"
    echo "     ./run_discovery.sh --show-data"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================

print_banner

if [ -z "$TARGET_DIR" ]; then
    show_usage
    exit 1
fi

# Absoluten Pfad ermitteln
TARGET_DIR="$(cd "$(dirname "$TARGET_DIR")" 2>/dev/null && pwd)/$(basename "$TARGET_DIR")" || TARGET_DIR="$1"

echo "Zielverzeichnis: $TARGET_DIR"
echo ""

# Prüfe ob Quellverzeichnis existiert
if [ ! -d "$SCRIPT_DIR/tests/hana04_discovery" ]; then
    log_error "Quellverzeichnis nicht gefunden: $SCRIPT_DIR/tests/hana04_discovery"
    log_error "Bitte deploy.sh aus dem Projekt-Root ausführen."
    exit 1
fi

# Abhängigkeiten prüfen
check_dependencies || exit 1
echo ""

# Deployment durchführen
deploy_files
create_hosts_file
fix_imports

# Zusammenfassung
print_summary
