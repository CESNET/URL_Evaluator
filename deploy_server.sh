#!/bin/bash

# 1. Pull kódu z vetvy
git pull origin feat-content-storage-and-sandbox
echo "code was pulled"

./install/migrate.sh

# 2. Reštart GUI (httpd)
sudo systemctl restart httpd 
echo "GUI was restarted"

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