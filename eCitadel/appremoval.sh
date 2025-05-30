#!/bin/bash

# Define the appremoval function
appremoval() {
  for app in "$@"; do
    echo "Removing $app..."

    # Remove the package and common variants
    sudo dnf remove -y "$app" "$app-cli" "$app-qt" >/dev/null 2>&1

    # Remove global config files if they exist
    if [ -d "/etc/${app}" ]; then
      echo "Removing /etc/${app}"
      sudo rm -rf "/etc/${app}"
    fi

    echo "$app removed (if it was installed)."
  done
}

# Remove common hacking/malware tools
appremoval \
wireshark \
nmap \
netcat \
nc \
hydra \
john \
aircrack-ng \
tcpdump \
ettercap \
nikto \
metasploit \
sqlmap \
binwalk \
radare2 \
gobuster \
recon-ng \
beef \
socat \
hping3 \
maltego \
hashcat \
ophcrack \
zmap \
dnsenum \
arp-scan \
dsniff \
yersinia \
burpsuite \
medusa \
fierce \
kismet \
wifite \
fern-wifi-cracker \
reaver \
enum4linux \
smbmap \
crackmapexec \
exploitdb \
dirb \
dirbuster \
proxychains \
powersploit \
empire \
veil \
evil-winrm \
responder \
impacket \
freeradius-wpe \
xspy \
xprobe \
snort \
openvas \
nessus \
chkrootkit \
rkhunter \
clamav
