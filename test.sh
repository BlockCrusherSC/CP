#!/bin/bash
#cp /etc/sudoers /etc/sudoers.bak

# Use sed to replace the line containing "Defaults"
#sed -i '/^Defaults /c\Defaults use_pty' /etc/sudoers

# Validate the sudoers file for syntax correctness
#visudo -c
#if [ $? -eq 0 ]; then
#    echo "The sudoers file was updated and is valid."
#else
#    echo "The sudoers file is invalid. Restoring the original."
#    mv /etc/sudoers.bak /etc/sudoers
#    exit 1
#fi

#grep -Pi
#'^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)
#(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\
#h+.*)?$' /etc/pam.d/su

sed -i  '/try_first_pass yescrypt/ { /remember=5/! s/$/ remember=5 / }' /etc/pam.d/common-password
sed -i  '/try_first_pass yescrypt/ { /minlen=10/! s/$/ minlen=10 / }' /etc/pam.d/common-password
sed -i  '/pam_pwquality.so/ { /ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/! s/$/ ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 / }' /etc/pam.d/common-password
