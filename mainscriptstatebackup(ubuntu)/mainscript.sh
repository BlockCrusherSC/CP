#!/bin/bash
BACKUPDIR="backupdir"
LOG_FILE="actions.log"
MANUAL_FILE="manual.log"
START_TIME=$(date +%s)
GREEN="\033[1;092m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"
function printlog() {
	CURRENT_TIME=$(date +%s)
	ELAPSED_TIME=$((CURRENT_TIME - START_TIME))

	ELAPSED_HOURS=$((ELAPSED_TIME / 3600))
	ELAPSED_MINUTES=$(((ELAPSED_TIME % 3600) / 60))
	ELAPSED_SECONDS=$((ELAPSED_TIME % 60))
	DURATION=$(printf "%02d:%02d:%02d" $ELAPSED_HOURS $ELAPSED_MINUTES $ELAPSED_SECONDS)

	echo -e "${CYAN}$1${RESET}"
	printf "${YELLOW}%s - %s - ${CYAN}%s${RESET}\n" "$(date +"%Y-%m-%d")" "$DURATION" "$*"  >> "$LOG_FILE"
}
function manualtask() {
echo -e "${GREEN}$1\n${RESET}" | sudo tee -a $MANUAL_FILE
}
touch actions.log
touch manual.log
chmod 777 "$LOG_FILE"
chmod 777 "$MANUAL_FILE"
> "$LOG_FILE"
> "$MANUAL_FILE"
printlog "Script Started."
#Ensure importfiles folder is installed
echo -e "${RED}UPDATE AND UPGRADE FIRST!!! Is importfiles installed and taken out of downloads, and file paths for required services (like apache2) have been confirmed?${RESET}"
read importfiles
if [[ $importfiles == "yes" || $importfiles == "y" ]];
then
	echo "Proceeding with script..."
else
	echo "Exiting..."
	exit
fi
# Backup Files
printlog "Backing up important files..."
mkdir -pv $BACKUPDIR
chmod 777 $BACKUPDIR

cp /etc/group $BACKUPDIR/group
chmod 777 $BACKUPDIR/group
cp /etc/passwd $BACKUPDIR/passwd
chmod 777 $BACKUPDIR/passwd
printlog "/etc/passwd and /etc/group has been backed up in the backups folder."

#Password Policies

	#common-password
printlog "Configuring passworld policies..."
cp /etc/pam.d/common-password $BACKUPDIR/common-password
chmod 777 $BACKUPDIR/common-password
printlog "common-password backed up."
sed -i '/pam_pwquality\.so/d' /etc/pam.d/common-password >> $LOG_FILE
printlog "pwquality removed from common-password."
sed -i  '/try_first_pass yescrypt/ { /remember=5/! s/$/ remember=5 / }' /etc/pam.d/common-password
sed -i  '/try_first_pass yescrypt/ { /minlen=8/! s/$/ minlen=8 / }' /etc/pam.d/common-password
sed -i  '/pam_cracklib.so/ { /ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/! s/$/ ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 / }' /etc/pam.d/common-password

	#libpam-cracklib
printlog "Installing libpam-cracklib..."
apt-get install libpam-cracklib -y >> $LOG_FILE
echo ""
printlog "libpam-cracklib installed."

	#login.defs
cp /etc/login.defs $BACKUPDIR/login.defs
chmod 777 $BACKUPDIR/login.defs
printlog "login.defs backed up."
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

    #No null passwords/common-auth
cp /etc/pam.d/common-auth $BACKUPDIR/common-auth
chmod 777 $BACKUPDIR/common-auth
printlog "common-auth backed up."
sed -i 's/*pam.unix.so nullok*/pam.unix.so/' /etc/pam.d/common-auth
printlog "Password policies configured."

#Account lockout policy
touch /usr/share/pam-configs/faillock >> $LOG_FILE
echo -e "Name: Enforce failed login attempt counter\nDefault: no\nPriority: 0\nAuth-Type: Primary\nAuth:\n	[default=die] pam_faillock.so authfail\n	sufficient pam_faillock.so authsucc" | sudo tee -a /usr/share/pam-configs/faillock
touch /usr/share/pam-configs/faillock_notify >> $LOG_FILE
echo -e "Name: Notify on failed login attempts\nDefault: no\nPriority: 1024\nAuth-Type: Primary\nAuth:\n	requisite pam_faillock.so preauth\n" | sudo tee -a /usr/share/pam-configs/faillock-notify

#Enable Firewall
printlog "Enabling firewall..."
apt-get install ufw -y -qq >> $LOG_FILE
ufw enable >> $LOG_FILE
ufw default deny incoming >> $LOG_FILE
ufw default allow outgoing >> $LOG_FILE
ufw deny 1337 >> $LOG_FILE
printlog "Firewall enabled and port 1337 closed."

#Shadow File Perms
chmod 640 /etc/shadow >> $LOG_FILE
printlog "Shadow file permissions configured."

#Secure sysctl
cp /etc/sysctl.conf $BACKUPDIR/sysctl.conf
chmod 777 $BACKUPDIR/sysctl.conf
printlog "sysctl.conf backed up."
cp importfiles/sysctl.conf /etc/sysctl.conf
chmod 600 /etc/sysctl.conf
printlog "sysctl.conf permissions configured."
printlog "sysctl.conf configured."

#Allow only root in cron
touch /etc/cron.allow
touch /etc/cron.deny
chmod 600 /etc/cron.allow >> $LOG_FILE
chmod 600 /etc/cron.deny >> $LOG_FILE
chmod 700 /var/spool/cron/crontabs >> $LOG_FILE
printlog "Cron directories limited & created if they didn't exist."

#Remove startup tasks from crontab
crontab -l > /importfiles/cronjobs.txt
printlog "crontab jobs backed up."
crontab -r >> $LOG_FILE
printlog "Root crontab scheduled jobs removed with crontab -r."

#Graphics software configuration
#printlog "Does the computer use LightDM?"
#read lightdm
#if [[ $lightdm == yes || $lightdm == y ]];
#Need to add another in case GNOME is installed
#then
	#cp /etc/lightdm/lightdm.conf $BACKUPDIR/lightdm.conf
	#chmod 777 $BACKUPDIR/lightdm.conf
	#printlog "lightdm.conf backed up."
	#cp importfiles/lightdm.conf /etc/lightdm/lightdm.conf
	#chmod 600 /etc/lightdm/lightdm.conf
	#printlog "lightdm.conf permissions configured."
#fi
#printlog "Does this computer use GNOME?"
#read gnome
#if [[ $gnome == yes || $gnome == y ]];
#then
#manualtask "In Settings > Sharing, turn off any screen sharing or remote login options"
#manualtask "Go to Settings > Privacy > Screen Lock and ensure it’s enabled"
# echo "..."
#printlog "GNOME configured."
#fi

#Set UID 0 to root
rootuid=$(id -u root)
if [[ $rootuid == 0 ]];
then
	printlog "Root UID is already 0. No changes needed."
else
	printlog "Root UID is not 0. Fixing..."
	sed -i 's/^root:x:1:0:/root:x:0:0:/' /etc/passwd
#	find / -user "$rootuid" -exec chown root {} \;
	printlog "UID for root set to 0 and ownership of files has been fixed."
fi

#Lock Root Account
passwd -l root >> $LOG_FILE
printlog "Root account locked."

#Unalias accounts
unalias -a
printlog "All alias have been removed."

#Remove Malicious Processes
function appremoval () {
    sudo apt-get purge --auto-remove -y -qq "$1" >> $LOG_FILE
    printlog "$1 removed."
}
appremoval lighttpd
appremoval nikto
appremoval nmap
appremoval tcpdump
appremoval wireshark
appremoval zenmap
appremoval logkeys
appremoval snmpd
appremoval inetutils-inetd
appremoval john
appremoval john-data
appremoval hydra
appremoval hydra-gtk
appremoval aircrack-ng
appremoval fcrackzip
appremoval lcrack
appremoval ophcrack
appremoval ophcrack-cli
appremoval pdfcrack
appremoval pyrit
appremoval rarcrack
appremoval sipcrack
appremoval irpas
appremoval zeitgeist-core
appremoval zeitgeist-datahub
appremoval python-zeitgeist
appremoval rhythmbox-plugin-zeitgeist
appremoval zeitgeist
appremoval burpsuite
appremoval netcat
appremoval netcat-openbsd
appremoval natcat-traditional
appremoval ncat
appremoval pnetcat
appremoval socat
appremoval sock
appremoval socket
appremoval sbd
apt-get purge aisleriot gnome-mahjongg gnome-mines gnome-sudoku -y -qq >> $LOG_FILE
printlog "Common games removed."

manualtask "Applications with hack or crack in the name (remove these):"
dpkg -l | grep -E 'hack|crack' >> $MANUAL_FILE
printlog "Common hacking tools removed, and apps with hack or crack have been scanned for."

#Install AppArmor
apt-get install apparmor apparmor-utils apparmor-profiles -y -qq >> $LOG_FILE
systemctl start apparmor >> $LOG_FILE 2>&1
systemctl enable apparmor >> $LOG_FILE 2>&1
printlog "AppArmor installed, started, and enabled by default."

#Disable Ctrl+Alt+Delete Reboot
echo "exec true" >> /etc/init/control-alt-delete.override
printlog "Ctrl+Alt+Delete reboot disabled."

#rc.local
if systemctl is-active --quiet rc-local.service;
then
	echo "rc-local.service is active."

        # Stop and disable the rc-local service
	cp /etc/rc.local $BACKUPDIR/rc.local
	chmod 777 $BACKUPDIR/rc.local
	printlog "rc.local has been backed up."
        sudo systemctl stop rc-local.service
        sudo systemctl disable rc-local.service
        sudo rm -f /etc/rc.local
        echo "rc.local has been removed and the service is disabled."
else
        echo "rc-local.service is not active."
fi

#Optional Applictions
    #SSH
echo "Does this computer need SSH?"
read sshstatus
if [[ $sshstatus == "yes" || $sshstatus == "y" ]];
then
	cp /etc/ssh/sshd_config $BACKUPDIR/sshd_config
	chmod 777 $BACKUPDIR/sshd_config
	printlog "sshd_config backed up."
	cp importfiles/sshd_config /etc/ssh/sshd_config
	chmod 600 /etc/ssh/sshd_config
	printlog "sshd_config permissions configured."
	printlog "For SSH: Default port changed, PermitRootLogin set to no, MaxAuthTries set to 3, Client closes after 4 minutes inactive, LoginGraceTime set to 20, PermitEmptyPasswords is set to no, HostBasedAuthentication set to no, and StrictModes is set to yes."
	systemctl restart sshd >> $LOG_FILE
	printlog "SSH restarted."
 	manualtask "Optional SSH tasks include MaxSessions, TCPKeepAlive, & changing default port."
elif [[ $sshstatus == "no" || $sshstatus == "n" ]];
then
	apt-get purge openssh-server openssh-client -y -qq >> $LOG_FILE
	ufw deny ssh >> $LOG_FILE
	printlog "SSH removed and SSH port closed."
else
	printlog "Invalid response given. SSH has not been configured."
fi

    #Samba
echo "Does this computer need Samba?"
read sambastatus
if [[ $sambastatus == "yes" || $sambastatus == "y" ]];
then
	echo "..."
elif [[ $sambastatus == "no" || $sambastatus == "n" ]];
then
	printlog "Removing Samba..."
	apt-get purge samba samba-common samba-libs samba-common-bin -y -qq >> $LOG_FILE
	printlog "Samba removed."

else
	printlog "Invalid response given. Samba has not been configured."
fi

    #FTP
echo "Does this computer need FTP?"
read ftpstatus
if [[ $ftpstatus == "yes" || $ftpstatus == "y" ]];
then
	echo "..."
elif [[ $ftpstatus == "no" || $ftpstatus == "n" ]];
then
	apt-get purge -y -qq vsftpd proftpd >> $LOG_FILE
	ufw deny ftp >> $LOG_FILE
	ufw deny sftp >> $LOG_FILE
 	ufw deny saft >> $LOG_FILE
  	ufw deny sftps >> $LOG_FILE
   	ufw deny sftps-data >> $LOG_FILE
    	printlog "FTP (vsftpd and proftpd) have been removed, and ufw has been configured."
else
	printlog "Invalid response given. FTPStatus has not been configured."
fi

    #Telnet
echo "Does this computer need Telnet?"
read telnetstatus
if [[ $telnetstatus == "yes" || $telnetstatus == "y" ]];
then
	echo"..."
elif [[ $telnetstatus == "no" || $telnetstatus == "n" ]];
then
	printlog "Removing telnet..."
	apt-get purge telnet telnetd -y -qq >> $LOG_FILE
	ufw deny 23 >> $LOG_FILE
	printlog "Telnet removed and port 23 closed."
else
	printlog "Invalid response given. Telnet has not been configured."
fi

    #Mail
echo "Does this computer need Mail?"
read mailstatus
if [[ $mailstatus == "yes" || $mailstatus == "y" ]];
then
	ufw allow imap >> $LOG_FILE #143
	ufw allow imap2 >> $LOG_FILE #143
	ufw allow imaps >> $LOG_FILE #993
	#ufw allow pop2 >> $LOG_FILE #109
    	ufw allow pop3 >> $LOG_FILE #110
	ufw allow pop3s >> $LOG_FILE #995
	ufw allow smtp >> $LOG_FILE #25, 587
	ufw allow smtps >> $LOG_FILE #465
	#ufw allow cso >> $LOG_FILE #105
	ufw allow ident >> $LOG_FILE #113
	ufw allow 106 >> $LOG_FILE #(3COM-TSMUX)
	printlog "imap, imap2, imaps, pop2, pop3, pop3s, smtp, smtps, cso, and ident ports have been allowed."
elif [[ $mailstatus == "no" || $mailstatus == "n" ]];
then
	ufw deny imap >> $LOG_FILE #143
	ufw deny imap2 >> $LOG_FILE #143
	ufw deny imaps >> $LOG_FILE #993
	#ufw deny pop2 >> $LOG_FILE #109
	ufw deny pop3 >> $LOG_FILE #110
	ufw deny pop3s >> $LOG_FILE #995
	ufw deny smtp >> $LOG_FILE #25, 587
	ufw deny smtps >> $LOG_FILE #465
	#ufw deny cso >> $LOG_FILE #105
	ufw deny ident >> $LOG_FILE #113
	ufw deny 106 >> $LOG_FILE #(3COM-TSMUX)
	printlog "imap, imap2, imaps, pop2, pop3, pop3s, smtp, smtps, cso, and ident ports have been closed."
else
	printlog "Invalid response given. Mail has not been configured."
fi

    #Printing
echo "Does this computer need Printing?"
read printstatus
if [[ $printstatus == "yes" || $printstatus == "y" ]];
then
	ufw allow ipp >> $LOG_FILE
	ufw allow printer >> $LOG_FILE
	ufw allow cups >> $LOG_FILE
	printlog "ipp, printer, and cups ports have been opened."
elif [[ $printstatus == "no" || $printstatus == "n" ]];
then
	ufw deny ipp >> $LOG_FILE
	ufw deny printer >> $LOG_FILE
	ufw deny cups >> $LOG_FILE
	printlog "ipp, printer, and cups ports have been closed."
else
	printlog "Invalid response given. Printing has not been configured."
fi

    #MySQL
echo "Does this computer need MySQL?"
read mysqlstatus
if [[ $mysqlstatus == "yes" || $mysqlstatus == "y" ]];
then
	echo "..."
elif [[ $mysqlstatus == "no" || $mysqlstatus == "n" ]];
then
	apt-get purge mysql-server mysql-client mysql-common mysql-server-core-* mysql-client-core-* -y -qq >> $LOG_FILE
 	rm -rf /etc/mysql /var/lib/mysql >> $LOG_FILE
  	ufw deny 3306
     	printlog "MySQL removed, group deleted, and port 3306 closed."
else
	printlog "Invalid response given. MySQL has not been configured."
fi

    #Web Servers
echo "Does this computer need apache2?"
read apache
if [[ $apache == "yes" || $apache == "y" ]];
then
	ufw allow http >> $LOG_FILE
 	ufw allow https >> $LOG_FILE
	printlog "HTTP and HTTPS ports opened."
 	cp /etc/apache2/apache2.conf $BACKUPDIR/apache2.conf
  	chmod 777 $BACKUPDIR/apache2.conf
  	printlog "apache2.conf backed up."
	cp importfiles/apache2.conf /etc/apache2/apache2.conf
 	printlog "apache2.conf configured."
   	sudo chown root:root /etc/apache2/apache2.conf >> $LOG_FILE
    	chmod 644 /etc/apache2/apache2.conf >> $LOG_FILE
     	"apache2.conf ownership and permissions set."
	
elif [[ $apache == "no" || $apache == "n" ]];
then
  	apt-get purge apache2 apache2-utils apache2-bin apache2.2-common -y -qq >> $LOG_FILE
     	printlog "apache2 removed."
else
	printlog "Invalid response given. Apache2 has not been configured."
fi

echo "Does this computer need nginx?"
read nginx
if [[ $nginx == "yes" || $nginx == "y" ]];
then
	echo "..."
elif [[ $nginx == "no" || $nginx == "n" ]];
then
	apt-get purge nginx nginx-full nginx-extras -y -qq >> $LOG_FILE
 	printlog "nginx removed."
else
	printlog "Invalid response given. Nginx has not been configured."
fi
	
echo "Can users have media files?"
read mediastatus
if [[ $mediastatus == "no" || $mediastatus == "n" ]];
then
	#audio files
	find /home -type f \( -name "*.midi" -o -name "*.mid" -o -name "*.mp3" -o -name "*.mp2" -o -name "*.mpa" -o -name "*.abs" -o -name "*.mpega" -o -name "*.au" -o -name "*.snd" -o -name "*.aiff" -o -name "*.aif" -o -name "*.sid" -o -name "*.flac" \) -delete 2>> $LOG_FILE
	printlog "Audio files removed."
	#video files
	find /home -type f \( -name "*.mpeg" -o -name "*.mpe" -o -name "*.dl" -o -name "*.movie" -o -name "*.movi" -o -name "*.mv" -o -name "*.iff" -o -name "*.anim5" -o -name "*.anim3" -o -name "*.anim7" -o -name "*.avi" -o -name "*.vfw" -o -name "*.avx" -o -name "*.fli" -o -name "*.flc" -o -name "*.mov" -o -name "*.qt" -o -name "*.spl" -o -name "*.swf" -o -name "*.dcr" -o -name "*.dxr" -o -name "*.rpm" -o -name "*.rm" -o -name "*.smi" -o -name "*.ra" -o -name "*.ram" -o -name "*.rv" -o -name "*.wmv" -o -name "*.asf" -o -name "*.asx" -o -name "*.wma" -o -name "*.wax" -o -name "*.wmv" -o -name "*.wmx" -o -name "*.3gp" -o -name "*.mov" -o -name "*.mp4" -o -name "*.avi" -o -name "*.swf" -o -name "*.flv" -o -name "*.m4v" \) -delete 2>> $LOG_FILE
	printlog "Video files removed."
	#image files
	find /home -type f \( -name "*.tiff" -o -name "*.tif" -o -name "*.rs" -o -name "*.im1" -o -name "*.gif" -o -name "*.jpeg" -o -name "*.jpg" -o -name "*.jpe" -o -name "*.png" -o -name "*.rgb" -o -name "*.xwd" -o -name "*.xpm" -o -name "*.ppm" -o -name "*.pbm" -o -name "*.pgm" -o -name "*.pcx" -o -name "*.ico" -o -name "*.svg" -o -name "*.svgz" \) -delete 2>> $LOG_FILE
	printlog "Image files removed."
	printlog "All media files have been removed within /home directories."
else
	printlog "Media files have not been configured."
fi

#Remove Unecessary Packages
apt-get autoclean -y -qq >> $LOG_FILE
apt-get clean -y -qq >> $LOG_FILE
printlog "Unecessary packages removed."

#---------- MANUAL TASKS -----------#

#Enable lockout policy
manualtask "ENABLE LOCKOUT POLICY (sudo pam-auth-update, and select 'Notify on failed login attempts' and 'Enforce failed login attempt counter'."
manualtask "AUTOREMOVE apt-get autoremove"
#Debsums scan
apt-get install debsums -y -qq >> $LOG_FILE
apt-get --reinstall -d install 'debsums -l' -y -qq >> $LOG_FILE
printlog "Debsums installed."
manualtask "Running debsums scan..."
debsums -s -a >> $LOG_FILE 2>> $LOG_FILE
printlog "Debsums scan complete. Review results in manual log."

#Strange admins
manualtask "Check for strange administrators:"
mawk -F: '$1 == "sudo"' /etc/group >> $MANUAL_FILE

#Strange users
manualtask "Check for strange users:"
mawk -F: '$3 < 1000 || $3 > 65533 {print $1, $3}' /etc/passwd >> $MANUAL_FILE

#Check listening processes
manualtask "Check listening processes:"
ss -tulnp >> $MANUAL_FILE

#Check startup
manualtask "Run sudo nano /etc/crontab and crontab -l to check startup (NETCAT BACKDOOR HERE!!!)\ncheck cron weekly, daily, hourly too"

#Files with perms of 700-777
manualtask "Check files with a permission of 700-777:"
ls -l | grep "^-rw[x-]*" >> $MANUAL_FILE

#Other
manualtask "Configure users (unathorized, auto-login, insecure password, privileges)"
manualtask "Configure groups"
manualtask "Configure browser"
manualtask "Configure Apparmor"
manualtask "Configure settings & Software & Updates"

#clamscan
echo "Do you want to clamscan?"
read clam
if [[ $clam == "yes" || $clam == "y" ]];
then
	apt-get install clamav -y -qq >> $LOG_FILE
	printlog "clamav installed. Running clamscan (will take a LONG time)..."
	manualtask "Clamscan infected files:"
	clamscan --bell --recursive -i >> $MANUAL_FILE
	printlog "Scan complete."
	manualtask "Scan complete."
 else
 	printlog "Clamscan not run."
fi

printlog "Script Complete."
