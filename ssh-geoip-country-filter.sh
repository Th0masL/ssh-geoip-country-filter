#!/bin/bash
# 
# SSH GeoIP Country Filter
# This script receive an IP in parameter, and returns TRUE (exit 0) if this IP is allowed and FALSE (exit 1) if it isn't
#
# Inspired from the article and comments of the following page :
# https://www.claudiokuenzler.com/blog/676/ssh-access-filter-based-on-geoip-database-allow-deny
#
# I've simply :
# - re-packaged it in a script that makes it easier to use
# - added automatic download of the MaxMind Database
# - added safety checks to prevent being locked out of the server in case of mistake/errors in the configuration
# 
# ===========================================
#
# Requirements :
#
# Packages :
# - mmdb-bin : to be able to use the command 'mmdblookup'
# - grepcidr : to be able to test single IPs against the CIDR notation
# 
# Add the following line in /etc/hosts.deny :
# sshd: ALL
#
# Add the following line in /etc/hosts.allow :
# sshd: ALL: aclexec /scripts/ipfilter.sh %a
#
# If you want to use the IP-to-Country lookup, you will have to create an account on Max
# 
# ===========================================
#
# You can verify the behavior of the script by using the following command :
# grep "sshd connection" /var/log/auth.log
#
# And the output should be something like that :
#
# Feb  5 01:11:50 server1 root: DENY sshd connection from 162.142.125.54 (US)
# Feb  5 01:53:00 server1 root: DENY sshd connection from 167.99.198.85 (GB)
# Feb  6 10:18:50 server1 root: DENY sshd connection from 213.108.134.156 (RU)
# Feb  6 15:43:38 server1 root: ALLOW sshd connection from 192.168.1.11 (Whitelisted)
#
# ===========================================
#
# Note :
# To avoid locking yourself out of your server, the script will automatically default to allowing the connection in case of errors.
#
# ===========================================
#

# Detect the folder where the script is located, and the script name
script_name=$( basename "$0" | awk -F '/' '{print $NF}' )
script_directory="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
script_path="$script_directory/$script_name"

# Make sure that we received at least 1 argument. This argument should be an IP address. We return TRUE (errorlevel:0) anyway, to avoid being locked out of the server.
if [[ $# -ne 1 ]]; then
	echo "Usage: `basename $0` <ip_adddress>"
	exit 0  # return true
fi

# Save the IP to a variable
IP_ADDRESS="$1"

# Define some default values. This can be overwritten by the variables defined in the file config.ini
ALLOW_IPS="192.168.0.0/24 192.168.1.0/24 192.168.2.0/24" # Allow SSH connections from some of the most common LAN subnets
ALLOW_COUNTRIES="" # By default, do not allow any country
LICENSE_KEY="" # By default, do not use a MaxMind Database
LOG_FACILITY="authpriv.notice" # Name of the Log Facility to use to log to syslog/auth. You most likely don't have to touch this.
MMDB_REFRESH_FREQUENCY=31 # Frequency of refresh for the MaxMind DB if in use. You most likely don't have to touch this.
MMDB_GEOIP_FILE="/tmp/GeoLite2-Country.mmdb" # Location of where to save the MaxMind *.mmdb file. You most likely don't have to touch this.

# Check if the config.ini file exist, and load the values from it
if [[ -f "$script_directory/config.ini" ]]; then
	source "$script_directory/config.ini"
fi

###### BASIC CHECKS TO VERIFY THE REQUIREMENTS ARE MET ######

# Allow the connection if we expect to use a Country Filter but the MaxMind License Key is missing
if [[ ! -z "$ALLOW_COUNTRIES" && -z "$LICENSE_KEY" ]]; then
	logger -s -p $LOG_FACILITY "ALLOW sshd connection from $IP_ADDRESS (Error: ALLOW_COUNTRIES is set but LICENSE_KEY is empty)"
	exit 0 # return true
fi

# Allow the connection if there are no Countries and no IPs Whitelist
if [[ -z "$ALLOW_COUNTRIES" && -z "$ALLOW_IPS" ]]; then
	logger -s -p $LOG_FACILITY "ALLOW sshd connection from $IP_ADDRESS (Error: Both ALLOW_COUNTRIES and ALLOW_IPS are empty)"
	exit 0 # return true
fi

# Allow the connection if some binaries are missing
if [[ ! $( which grepcidr ) ]]; then
	logger -s -p $LOG_FACILITY "ALLOW sshd connection from $IP_ADDRESS (Error: The grepcidr binary is missing. Please install it using 'apt-get install grepcidr')"
	exit 0 # return true
fi
if [[ ! $( which mmdblookup ) ]]; then
	logger -s -p $LOG_FACILITY "ALLOW sshd connection from $IP_ADDRESS (Error: The mmdblookup binary is missing. Please install it using 'apt-get install mmdb-bin'.)"
	exit 0 # return true
fi

# Allow the connection if the file /etc/hosts.deny does not contains the required line
if [[ ! -f /etc/hosts.deny || -z $( cat /etc/hosts.deny | grep "^sshd: ALL$" ) ]]; then
	logger -s -p $LOG_FACILITY "ALLOW sshd connection from $IP_ADDRESS (Error: Invalid content in /etc/hosts.deny)"
	exit 0 # return true
fi

# Allow the connection if the file /etc/hosts.allow does not contains the required line
if [[ ! -f /etc/hosts.allow || -z $( cat /etc/hosts.allow | grep "^sshd: ALL: aclexec $script_path %a$" ) ]]; then
	logger -s -p $LOG_FACILITY "ALLOW sshd connection from $IP_ADDRESS (Error: Invalid content in /etc/hosts.allow)"
	exit 0 # return true
fi

###### VERIFY IF THE IP ITSELF IS WHITELISTED ######

# First we check if the IP is part of the Whitelisted IPs, and if it is, we will exit now with TRUE(errorlevel:0)
if [[ ! -z "$ALLOW_IPS" ]]; then

	# Test the IP against the list of Whitelisted IPs
	echo $IP_ADDRESS | grepcidr "$ALLOW_IPS" &> /dev/null
	grepcidr_errorlevel=$?
 
	# If the grepcidr_errorlevel result is 0, it means that this IP is in the list of Whitelisted IPs, so we log an ALLOW message in syslog and we exit with TRUE(errorlevel:0)
	if [[ $grepcidr_errorlevel -eq 0 ]]; then
		logger -s -p $LOG_FACILITY "ALLOW sshd connection from $IP_ADDRESS (Whitelisted)"
		exit 0 # return true
	fi
fi

###### IF THE IP ITSELF IS NOT WHITELISTED, VERIFY IF THE COUNTRY IS WHITELISTED ######

# If the MaxMind License Key is defined in the config, then we will download the MaxMind Country Database File to be able to detect the country of the IP Address
if [[ ! -z "$LICENSE_KEY" ]]; then
	# If the MMDB GEOIP file is already present, check when it was generated
	if [[ -f "$MMDB_GEOIP_FILE" ]]; then
		mmdb_last_update_date_epoch=$( stat -c %Y "$MMDB_GEOIP_FILE" )
		date_now_epoch=$( date "+%s" )
		last_mmdb_refresh_in_minutes=$( echo "($date_now_epoch - $mmdb_last_update_date_epoch) / 60" | bc )
		last_mmdb_refresh_in_days=$( echo "$last_mmdb_refresh_in_minutes / 1440" | bc )
	else # If the file is not here, set the value to 0
		last_mmdb_refresh_in_days=0
		last_mmdb_refresh_in_minutes=0
	fi

	# If the MMDB GEOIP file is missing, or if it was last refreshed more than MMDB_REFRESH_FREQUENCY days ago, download it
	if [[ ! -f "$MMDB_GEOIP_FILE" || $last_mmdb_refresh_in_days > $MMDB_REFRESH_FREQUENCY ]]; then
		# If there is already a tar.gz file, delete it so we can re-download it
		if [[ -f "/tmp/GeoLite2-Country.tar.gz" ]]; then
			rm -f "/tmp/GeoLite2-Country.tar.gz"
		fi

		# Download the new tar.gz file
		wget -O /tmp/GeoLite2-Country.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=$LICENSE_KEY&suffix=tar.gz" 2>/dev/null
		wget_errorlevel=$?

		# In case of error with the download, we allow the connection but log the error in syslog
		if [[ $wget_errorlevel -ne 0 ]]; then
			logger -s -p $LOG_FACILITY "ALLOW sshd connection from $IP_ADDRESS (due not being able to download the DB file)"
			exit 0 # return true
		fi

		# If the tar.gz file is here, extract it
		if [[ -f "/tmp/GeoLite2-Country.tar.gz" ]]; then
			tar xzf /tmp/GeoLite2-Country.tar.gz -C /tmp/ 2>/dev/null
			tar_errorlevel=$?

			# In case of error with the file we've just extracted, we allow the connection but log the error in syslog
			if [[ $tar_errorlevel -ne 0 ]]; then
				logger -s -p $LOG_FACILITY "ALLOW sshd connection from $IP_ADDRESS (due not being able to extract the DB file from /tmp/GeoLite2-Country.tar.gz)"
				exit 0 # return true
			fi

			# Try to detect the most up-to-date GeoLite2-Country.mmdb file in /tmp/
			new_mmdb_file=$( find /tmp/ -type f -name "GeoLite2-Country.mmdb" 2>/dev/null | sort --version-sort -r | grep -v "$MMDB_GEOIP_FILE" | head -1 )

			# If we found a file, we save it to the expected path
			if [[ -f "$new_mmdb_file" ]]; then
				# If the new file is different than the existing file, overwrite it
				if [[ "$new_mmdb_file" != "$MMDB_GEOIP_FILE" ]]; then
					cp "$new_mmdb_file" "$MMDB_GEOIP_FILE"
				else # Else no need to overwrite it, but we touch the existing file to update the timestamps of modification, so we don't try to re-download it before the usual MMDB_REFRESH_FREQUENCY days
					touch "$MMDB_GEOIP_FILE"
				fi
			else # If for some reason we've not been able to find any GeoLite2-Country.mmdb file in /tmp/, allow the connection and show an error message in syslog
				logger -s -p $LOG_FACILITY "ALLOW sshd connection from $IP_ADDRESS (Error: Unable to find the new GeoLite2-Country.mmdb file in the /tmp/ folder)"
				exit 0 # return true
			fi

			# Delete the tag.gz file
			rm -f "/tmp/GeoLite2-Country.tar.gz"
		fi
	fi

	# If the MaxMind GeoIP File is still missing after trying to generate it, then allow the connection and show an error message in syslog
	if [[ ! -f "$MMDB_GEOIP_FILE" ]]; then
		logger -s -p $LOG_FACILITY "ALLOW sshd connection from $IP_ADDRESS (Error: The MMDB GeoIP DB file missing and we have not been able to generate it)"
		exit 0 # return true
	fi

	# Run the Geoip-Lookup against this IP
	THIS_IP_COUNTRY="$( mmdblookup -f "$MMDB_GEOIP_FILE" -i "$IP_ADDRESS" country iso_code 2>&1 | awk '/".*"/{gsub(/"/,""); print $1 }')"

	# If we haven't been able to detect the country of this IP, assign a fake country code to 'ZZ' so we can test it anyway
	if [[ -z "$THIS_IP_COUNTRY" ]]; then
		THIS_IP_COUNTRY="ZZ"
	fi

	# Check if this country code is in the list of the allowed countries
	if [[ "$ALLOW_COUNTRIES" =~ "$THIS_IP_COUNTRY" ]]; then
		logger -s -p $LOG_FACILITY "ALLOW sshd connection from $IP_ADDRESS ($THIS_IP_COUNTRY) - Last Country DB Refresh: $last_mmdb_refresh_in_days days ago ($last_mmdb_refresh_in_minutes minutes ago)"
		exit 0 # return true
	else
		logger -s -p $LOG_FACILITY "DENY sshd connection from $IP_ADDRESS ($THIS_IP_COUNTRY) - Last Country DB Refresh: $last_mmdb_refresh_in_days days ago ($last_mmdb_refresh_in_minutes minutes ago)"
		exit 1 # return false
	fi
else # If the MaxMind functionality is not enabled, exit with FALSE(errorlevel:1) and output a message in syslog)
	logger -s -p $LOG_FACILITY "DENY sshd connection from $IP_ADDRESS (Not found in the Whitelist, and the License Key is empty so we won't try to verify the country.)"
	exit 1 # return false
fi
