#!/bin/bash
#Debsums scan
apt-get install debsums
apt-get --reinstall -d install 'debsums -l'
echo "Debsums installed."
echo "Running debsums scan..."
debsums -s -a
echo "Debsums scan complete. Review results in manual log."
