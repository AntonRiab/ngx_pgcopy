#!/bin/sh
last_pid=$(cat /var/log/nginx-error.log | grep 'PGCOPY:' | tail -n1 | grep -oE '\[debug\] [0-9]*' | grep -oE '[0-9]*')
last_log=$(cat /var/log/nginx-error.log | awk -F ':' '/\[debug\] '$last_pid'/ && /PGCOPY:/ {print $5}' | sed 's/^ //')

echo "<?xml version="1.0"?><LOG_OUT>$last_log</LOG_OUT>" | xmllint --format --recover rs.xml -
