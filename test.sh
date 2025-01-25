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

#grep -PH -- '^\h*([^#\n\r]+\h+)?pam_unix\.so\h+([^#\n\r]+\h+)?nullok\b' /usr/share/pam-configs/*
#echo ""
#find /usr/share/pam-configs/ -type f -exec sed -i '/nullok/g' {} +
#echo ""
#grep -PH -- '^\h*([^#\n\r]+\h+)?pam_unix\.so\h+([^#\n\r]+\h+)?nullok\b' /usr/share/pam-configs/*

# Network Security
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1

# Resource Limits
fs.file-max = 1000000
fs.inotify.max_user_watches = 524288
kernel.pid_max = 65536
kernel.threads-max = 2048
fs.nr_open = 1048576

# Process Security and Memory Management
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.unprivileged_userns_clone = 0
kernel.yama.ptrace_scope = 1
vm.overcommit_memory = 2
vm.swappiness = 10
vm.max_map_count = 262144

# Security Logging
kernel.dmesg_restrict = 1

# General System Hardening
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_syn_backlog = 1024
kernel.unprivileged_bpf_disabled = 1

# Enable IP source routing protection
net.ipv4.conf.all.accept_source_route = 0

# Control network log martians (suspicious packets)
net.ipv4.conf.all.log_martians = 1

# Disable unprivileged BPF programs
kernel.unprivileged_bpf_disabled = 1

# Enable reverse path filtering (prevents IP spoofing)
net.ipv4.conf.all.rp_filter = 1

# Disable packet forwarding for IPv6
net.ipv6.conf.all.forwarding = 0

# Disable kernel pointer leaks
kernel.kptr_restrict = 2

# Disable the sending of ICMP redirects to avoid man-in-the-middle attacks
net.ipv4.conf.all.send_redirects = 0
