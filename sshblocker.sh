#!/bin/bash
sshlog="/var/log/easyids/ssh.log";
knownIpsFile="/etc/easyids/known_ips";
souspiciousIpsFile="/etc/easyids/souspicious_ips";
blockedIpsFile="/etc/easyids/blocked_ips";

function has() {
	local filename="$1";
	local value="$2"; 
	[[ -f $filename ]] || touch $filename;
	while IFS= read -r line; do
		if [[ "$line" == "$value" ]]; then
			return 0;
		fi
	done < $filename;
	return 1;
}
function isIp() { 
	if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		return 0
	else
		return 1
	fi
}

journalctl -f SYSLOG_FACILITY=10 | while read -r line; do
	line=$(echo $line | grep "authentication failure;");
	ip=$(echo $line | awk {'print $14'} | awk -F "=" {'print $2'})
	if isIp $ip; then 
		if has "$knownIpsFile" "$ip" && ! has "$blockedIpsFile" "$ip"; then
			if has "$souspiciousIpsFile" "$ip"; then
				iptables -A INPUT -p tcp --source $ip -j DROP
				echo $ip >> $blockedIpsFile
				echo "ip blocked: $ip" >> $sshlog
			else 
				echo $ip >> $souspiciousIpsFile;
				echo "souspicious ip: $ip" >> $sshlog
			fi
		else 
			echo $ip >> $knownIpsFile;
		fi
	fi
done
