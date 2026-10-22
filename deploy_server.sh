#!/bin/bash

# Usage: ./deploy_server.sh [--gui]
#   --gui  restart only the GUI (httpd), leave Supervisor services running

GUI_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --gui) GUI_ONLY=1 ;;
        *) echo "Unknown option: $arg (usage: $0 [--gui])"; exit 1 ;;
    esac
done

# 1. Pull kódu z vetvy
git pull origin feat-content-storage-and-sandbox
echo "code was pulled"\

# Zastavenie služieb pred migráciou, aby počas zálohy a migrácie nezapisovali do DB
# (znova sa spustia reštartom v kroku 3; pri --gui zostávajú bežať)
if [ "$GUI_ONLY" -eq 0 ]; then
    echo "Stopping Supervisor services before migration..."
    for service in activity_scanner db_cleaner evaluator honeynetasia2evaluator tpot2evaluator warden2evaluator; do
        supervisorctl stop "$service"
    done
fi

./install/migrate.sh

# 2. Reštart GUI (httpd)
sudo systemctl restart httpd 
echo "GUI was restarted"

if [ "$GUI_ONLY" -eq 1 ]; then
    echo "--gui: Supervisor services were not restarted"
    exit 0
fi

# 3. Reštart bežiacich služieb v Supervisorovi
echo "Restarting running Supervisor services..."

# Zoznam bežiacich služieb zistených zo statusu (activity_scanner, db_cleaner, evaluator, honeynetasia2evaluator, tpot2evaluator, warden2evaluator)
SERVICES="activity_scanner db_cleaner evaluator honeynetasia2evaluator tpot2evaluator warden2evaluator"

for service in $SERVICES; do
    echo "Restarting $service..."
    supervisorctl restart "$service"
done

echo "All running Supervisor services were restarted."

sudo systemctl restart httpd
echo "httpd was restarted"

# 4. Zobrazenie aktuálneho statusu všetkých služieb
echo "========================================="
supervisorctl status
echo "========================================="