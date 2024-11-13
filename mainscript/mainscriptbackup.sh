#!/bin/bash
BACKUPDIR="backupdir"
LOG_FILE="actions.log"
START_TIME=$(date +%s)
GREEN="\033[1;092m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
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
touch actions.log
chmod 777 "$LOG_FILE"
> "$LOG_FILE"
printlog "${RESET}Script Started. ${CYAN}Cyan text is a deliberate message${RESET}, and ${GREEN}green text is optional manual tasks to do.${RESET}"
# Backup Files
printlog "Backing up important files..."
mkdir -pv $BACKUPDIR
chmod 777 $BACKUPDIR

cp /etc/group $BACKUPDIR/group
chmod 777 $BACKUPDIR/group
cp /etc/passwd $BACKUPDIR/passwd
chmod 777 $BACKUPDIR
printlog "/etc/passwd and /etc/group has been backed up in the desktop backups folder."

#Password Policies

	#libpam-cracklib
printlog "Installing libpam-cracklib..."
apt-get install libpam-cracklib >> $LOG_FILE
echo ""
printlog "libpam-cracklib installed."

	#common-password:
printlog "Configuring passworld policies..."
sed -i  '/try_first_pass yescrypt/ { /remember=5/! s/$/ remember=5 / }' /etc/pam.d/common-password
sed -i  '/try_first_pass yescrypt/ { /minlen=8/! s/$/ minlen=8 / }' /etc/pam.d/common-password
sed -i  '/pam_cracklib.so/ { /ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/! s/$/ ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 / }' /etc/pam.d/common-password

	#login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
printlog "Password policies configured."

#Enable Firewall
printlog "Enabling firewall..."
apt-get install ufw -y -qq
ufw enable
ufw default deny incoming >> $LOG_FILE
ufw default allow outgoing >> $LOG_FILE
printlog "Firewall enabled."

#Optional Applictions
echo "Does this computer need SSH?"
read sshstatus
if [[ $sshstatus == "yes" || $sshstatus == "y" ]];
then
	sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config || echo "Port 2222" | sudo tee -a /etc/ssh/sshd_config
	ufw allow 2222 >> $LOG_FILE
	printlog "SSH port set to 2222"
	sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || echo "PermitRootLogin no" | sudo tee -a  /etc/ssh/sshd_config
	sed -i 's/^#\?MaxAuthTries .*/MaxAuthTries 3/' /etc/ssh/sshd_config || echo "MaxAuthTries 3" | sudo tee -a /etc/ssh/sshd_config
	sed -i 's/^#\?ClientAliveInterval .*/ClientAliveInterval 240/' /etc/ssh/sshd_config || echo "ClientAliveInterval 240" | sudo tee -a /etc/ssh/sshd_config
	sed -i 's/^#\?ClientAliveCountMax .*/ClientAliveCountMax 0/' /etc/ssh/sshd_config || echo "ClientAliveCountMax 0" | sudo tee -a /etc/ssh/sshd_config
	sed -i 's/^#\?LoginGraceTime .*/LoginGraceTime 20/' /etc/ssh/sshd_config || echo "LoginGraceTime 20" | sudo tee -a /etc/ssh/sshd_config
	sed -i 's/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" | sudo tee -a /etc/ssh/sshd_config
	printlog "For SSH: Default port changed, PermitRootLogin set to no, MaxAuthTries set to 3, Client closes after 4 minutes inactive, LoginGraceTime set to 20, & PermitEmptyPasswords is set to no ."
	systemctl restart sshd >> $LOG_FILE
	printlog "SSH restarted. ${GREEN}Optional SSH tasks include MaxSessions, TCPKeepAlive, & X11 Forwarding.${RESET}"
elif [[ $sshstatus == "no" || $sshstatus == "n" ]];
then
	systemctl stop ssh >> $LOG_FILE && sudo apt-get purge -y openssh-server >> $LOG_FILE && sudo apt-get autoremove -y >> $LOG_FILE
	printlog "SSH removed."
	ufw deny 2222 >> $LOG_FILE
else
	printlog "Invalid response given. SSH has not been configured."
fi
ufw deny 22 >> $LOG_FILE
printlog "Default SSH port closed."

echo "Does this computer need Samba?"
read sambastatus
if [[ $sambastatus == "yes" || $sambastatus == "y" ]];
then
	echo "..."
elif [[ $sambastatus == "no" || $sambastatus == "n" ]];
then
	printlog "Removing Samba..."
	systemctl stop samba >> $LOG_FILE && sudo apt-get purge -y samba >> $LOG_FILE && sudo apt-get autoremove -y >> $LOG_FILE
	printlog "Samba removed."
	echo "Is File and Printer Sharing needed?"
	read fileprintshare
	if [[ $fileprintshare == "no" || $fileprintshare == "n" ]];
	then
		printlog "Closing Samba/File & Printer Sharing ports..."
		ufw deny 137, 138, 139, 445
		printlog "Ports 137, 138, 139, & 145 have been closed."
	else
		printlog "Ports 137,138, 139, & 145 have not been closed."
	fi
else
	printlog "Invalid response given. Samba has not been configured."
fi


echo "Does this computer need FTP?"
read ftpstatus
if [[ $ftpstatus == "yes" || $ftpstatus == "y" ]];
then

fi

echo "Does this computer need Telnet?"
#read telnetstatus
if [[ $telnetstatus == "yes" || $telnetstatus == "y" ]];
then

elif [[ $telnetstatus == "no" || $telnetstatus == "n" ]];

fi


echo "Does this computer need Mail?"
#read mailstatus
if [[ $mailstatus == "yes" || $mailstatus == "y" ]];
then

fi

echo "Does this computer need Print?"
#read printstatus
if [[ $printstatus == "yes" || $printstatus == "y" ]];
then

fi

echo "Does this computer need MySQL?"
#read mysqlstatus
if [[ $mysqlstatus == "yes" || $mysqlstatus == "y" ]];
then

fi

echo "Does this computer need DNS?"
#read dnsstatus
if [[ $dnsstatus == "yes" || $dnsstatus == "y" ]];
then

fi

#echo "Is this computer a Web Server?"

#echo "Can users have media files?"
#read mediafilestatus
