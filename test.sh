cp /etc/sudoers /etc/sudoers.bak

# Use sed to replace the line containing "Defaults"
sed -i '/^Defaults /c\Defaults use_pty' /etc/sudoers

# Validate the sudoers file for syntax correctness
visudo -c
if [ $? -eq 0 ]; then
    echo "The sudoers file was updated and is valid."
else
    echo "The sudoers file is invalid. Restoring the original."
    mv /etc/sudoers.bak /etc/sudoers
    exit 1
fi
