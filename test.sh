#!bin/bash
echo "Can users have media files? (COULD BREAK STUFF)"
read mediastatus
if [[ $mediastatus == "no" || $mediastatus == "n" ]];
then
	#audio files
	find / -type f \( -name "*.midi" -o -name "*.mid" -o -name "*.mp3" -o -name "*.mp2" -o -name "*.mpa" -o -name "*.abs" -o -name "*.mpega" -o -name "*.au" -o -name "*.snd" -o -name "*.wav" -o -name "*.aiff" -o -name "*.aif" -o -name "*.sid" -o -name "*.flac" -o -name "*.ogg" \) -delete 2>> $LOG_FILE
	printlog "Audio files removed."
	#video files
	find / -type f \( -name "*.mpeg" -o -name "*.mpg" -o -name "*.mpe" -o -name "*.dl" -o -name "*.movie" -o -name "*.movi" -o -name "*.mv" -o -name "*.iff" -o -name "*.anim5" -o -name "*.anim3" -o -name "*.anim7" -o -name "*.avi" -o -name "*.vfw" -o -name "*.avx" -o -name "*.fli" -o -name "*.flc" -o -name "*.mov" -o -name "*.qt" -o -name "*.spl" -o -name "*.swf" -o -name "*.dcr" -o -name "*.dxr" -o -name "*.rpm" -o -name "*.rm" -o -name "*.smi" -o -name "*.ra" -o -name "*.ram" -o -name "*.rv" -o -name "*.wmv" -o -name "*.asf" -o -name "*.asx" -o -name "*.wma" -o -name "*.wax" -o -name "*.wmv" -o -name "*.wmx" -o -name "*.3gp" -o -name "*.mov" -o -name "*.mp4" -o -name "*.avi" -o -name "*.swf" -o -name "*.flv" -o -name "*.m4v" \) -delete 2>> $LOG_FILE
	printlog "Video files removed."
	#image files
	find /home -type f \( -name "*.tiff" -o -name "*.tif" -o -name "*.rs" -o -name "*.im1" -o -name "*.gif" -o -name "*.jpeg" -o -name "*.jpg" -o -name "*.jpe" -o -name "*.png" -o -name "*.rgb" -o -name "*.xwd" -o -name "*.xpm" -o -name "*.ppm" -o -name "*.pbm" -o -name "*.pgm" -o -name "*.pcx" -o -name "*.ico" -o -name "*.svg" -o -name "*.svgz" \) -delete 2>> $LOG_FILE
	printlog "Image files removed."
	printlog "All media files have been removed."
else
	printlog "Media files have not been configured."
fi

