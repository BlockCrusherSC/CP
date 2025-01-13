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

grep -PH -- '^\h*([^#\n\r]+\h+)?pam_unix\.so\h+([^#\n\r]+\h+)?nullok\b' /usr/share/pam-configs/*
echo ""
find /usr/share/pam-configs/ -type f -exec sed -i '/^\h*([^#\n\r]+\h+)?pam_unix\.so\h+([^#\n\r]+\h+)?nullok\b/s/nullok//g' {} +
echo ""
grep -PH -- '^\h*([^#\n\r]+\h+)?pam_unix\.so\h+([^#\n\r]+\h+)?nullok\b' /usr/share/pam-configs/*
