#!/bin/bash
#Debsums scan
apt-get insall debsums
apt-get --reinstall -d install 'debsums -l'
printlog "Debsums installed."
manualtask "Running debsums scan..."
debsums -s -a
printlog "Debsums scan complete. Review results in manual log."
