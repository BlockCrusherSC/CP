#!/bin/bash
echo "Do you want to clamscan?"
read clam
if [[ $clam == "yes" || $clam == "y" ]];
then
  apt-get install clamav -y -qq >> $LOG_FILE
	printlog "clamav installed. Running clamscan (will take a LONG time)..."
	manualtask "Clamscan infected files:"
	clamscan -r --bell -i --exclude-dir="^/sys" / >> $MANUAL_FILE
	printlog "Scan complete."
	manualtask "Scan complete."
 else
 	printlog "Clamscan not run."
fi
