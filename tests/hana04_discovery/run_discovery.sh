#!/bin/bash
#
# Wrapper-Script für Discovery auf hana04
#
# Verwendung:
#   ./run_discovery.sh                    # Alle Discoveries ausführen
#   ./run_discovery.sh --list-rules       # Verfügbare Regeln anzeigen
#   ./run_discovery.sh -g system_info     # Nur system_info Gruppe
#   ./run_discovery.sh --show-data        # Ergebnisse am Ende anzeigen
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Python-Script ausführen
python3 "${SCRIPT_DIR}/discovery_runner.py" "$@"
