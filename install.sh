#!/bin/bash
set +x

function checkInstall() {
	$1 > /dev/null 2>&1
	result="$?"
	if [ "$result" -ne 0 ]; then
		echo "$2"
		echo "$?"
		exit 1;
	fi
}
checkInstall "dpkg -s python2.7" "please install python2.7"
checkInstall "dpkg -s python-pip" "please install python2.7-pip"

dest="/home/$USER/.r2scripts"
if [ -d "$dest" ]; then
	rm -rf "$dest"
fi

mkdir $dest

cp -a ./noAlarm $dest
cp -a ./restore $dest

r2file="/home/$USER/.radare2rc"
if [ ! -f "$r2file" ]; then
	echo "" > "$r2file"
fi


sed -i '/###R2SCRIPTS#START###/,/###R2SCRIPTS#END###/d' $r2file

cat << EOL >> $r2file
###R2SCRIPTS#START###
#####R2 RESTORE #####
\$save="#!pipe python2.7 $dest/restore/restore.py save"
\$load="#!pipe python2.7 $dest/restore/restore.py load"
\$saveFunc="#!pipe python2.7 $dest/restore/restore.py func save"
\$loadFunc="#!pipe python2.7 $dest/restore/restore.py func load"

#####R2 noAlarm ####
\$noAlarm=#!pipe python2.7 $dest/noAlarm/noAlarm.py
###R2SCRIPTS#END###
EOL
cat $r2file
