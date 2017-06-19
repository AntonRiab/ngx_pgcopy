#!/bin/sh
default_log="/var/log/nginx-error.log"
log_file=""

if [ $# -lt 1 -o ! -f $1 ]; then
    log_file=$default_log
    echo "Log file set to default: $default_log"
else
    log_file=$1
fi

if [ ! -f $log_file ];then
    echo "Log file not found, EXIT"
    printf "Set log file like:\n\tparse.log.sh PATH_LOG_FILE"
    exit
fi

last_pid=$(cat /var/log/nginx-error.log | grep 'PGCOPY:' | tail -n1 | grep -oE '\[debug\] [0-9]*' | grep -oE '[0-9]*')
last_log=$(cat /var/log/nginx-error.log | awk -F ':' '/\[debug\] '$last_pid'/ && /PGCOPY:/ {print $5}' | sed 's/^ //')

echo "<?xml version=\"1.0\"?><LOG_OUT>$last_log</LOG_OUT>" | tee ngx_pgcopy.log | xmllint --recover --format - | tee ngx_pgcopy.log.xml
