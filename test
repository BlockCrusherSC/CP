#!/bin/bash

echo "Configuring update settings..."

# Subscribe to "All updates"
sudo sed -i 's/^Prompt=.*/Prompt=normal/' /etc/update-manager/release-upgrades

# Set automatic update checks to daily
sudo sed -i 's/^APT::Periodic::Update-Package-Lists ".*";/APT::Periodic::Update-Package-Lists "1";/' /etc/apt/apt.conf.d/10periodic
sudo sed -i 's/^APT::Periodic::Download-Upgradeable-Packages ".*";/APT::Periodic::Download-Upgradeable-Packages "1";/' /etc/apt/apt.conf.d/10periodic
sudo sed -i 's/^APT::Periodic::Unattended-Upgrade ".*";/APT::Periodic::Unattended-Upgrade "1";/' /etc/apt/apt.conf.d/10periodic

# Security updates: Display immediately
sudo sed -i 's/^Update-Manager::Security-Updates ".*";/Update-Manager::Security-Updates "1";/' /etc/apt/apt.conf.d/10periodic

# Other updates: Display every two weeks
sudo sed -i 's/^APT::Periodic::AutocleanInterval ".*";/APT::Periodic::AutocleanInterval "14";/' /etc/apt/apt.conf.d/10periodic

# Notify me of a new Ubuntu version: Set to "never"
sudo sed -i 's/^Prompt=.*/Prompt=never/' /etc/update-manager/release-upgrades

echo "Update settings configured successfully!"
