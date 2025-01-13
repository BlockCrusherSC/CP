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

{
while IFS= read -r l_user; do
l_change=$(date -d "$(chage --list $l_user | grep '^Last password
change' | cut -d: -f2 | grep -v 'never$')" +%s)
if [[ "$l_change" -gt "$(date +%s)" ]]; then
echo "User: \"$l_user\" last password change was \"$(chage --list
$l_user | grep '^Last password change' | cut -d: -f2)\""
fi
done < <(awk -F: '$2~/^\$.+\$/{print $1}' /etc/shadow)
}
