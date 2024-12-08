#!/bin/bash

# 1. Making sure the script is executable 
chmod +x NR.sh

#  Checking to see if the packages needed in the script has been installed. 
# 	 Otherwise, to install the packages (whois, sshpass, nipe, geoiplookup, nmap)

# Function to check if a package is installed

check_package()
{
	which "$1" > /dev/null 2>&1
}

# Function to install a package

install_package()
{
	echo "Installing $1..."
	sudo apt-get install -y "$1"
}

# List of packages to check - whois, sshpass geoiplookup
packages=("whois" "sshpass" "geoiplookup" "nmap" "vsftpd")

for pkg in "${packages[@]}"
do
	if check_package "$pkg"
	then
		echo "$pkg is already installed."
		
		sleep 2
		
	else 
		
		echo "$pkg is not installed. We will proceed to install $pkg"
		install_package "$pkg"
		echo "$pkg has been installed."
		
		sleep 2
	fi
done

# Check if Nipe is installed

nipe_path=$(find ~ -name "nipe.pl" 2>/dev/null)

# Function for installing nipe
install_nipe()
{
	# check for updates
	sudo apt-get update -y
	
	echo "Updates have been completed. We will proceed to install Nipe."
	sleep 5
	
	git clone https://github.com/htrgouvea/nipe && cd nipe || { echo "Failed to clone Nipe repository."; exit 1; }
	sudo apt-get install -y cpanminus || { echo "Failed to install cpanminus."; exit 1; }
	cpanm --installdeps . || { echo "Failed to install dependencies using cpanminus."; exit 1; }
	sudo cpan install Switch JSON LWP::UserAgent Config::Simple || { echo "Failed to install required Perl modules."; exit 1; }
	sudo perl nipe.pl install || { echo "Failed to install Nipe."; exit 1; }
}

# If nipe has been installed, show file path
# If nipe is not installed, install nipe. 


if [ -n "$nipe_path" ]
then

    echo "Nipe has been installed"
    nipe_dir=$(dirname "$nipe_path")
    echo "Changing directory to $nipe_dir"
    cd "$nipe_dir" || { echo "Failed to change directory to $nipe_dir"; exit 1; }
    
	
else
	echo "Nipe has not been installed. We will be checking for updates and proceed to install Nipe"
	
	sleep 3
	
	install_nipe
	
	echo "Nipe has been successfully installed."
fi

sleep 3
echo
echo
echo

# 2. Connect to nipe

# Functions to get spoofed ip address and spoofed country
function get_spoofed_ip()
{
	sudo perl nipe.pl status | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
}


function get_spoofed_country()
{
    ip=$1
    geoiplookup "$ip" | grep "GeoIP Country Edition:" | awk -F: '{ print $2 }'
}


# Function for activation of nipe
function nipe_activation()
{
	sudo perl nipe.pl status | grep -c "true"
}
nipe_activate=$(nipe_activation)


# Check if nipe is activated

echo "Checking for nipe status..."
echo
echo

# if nipe is activated = 0, if nipe is activated = 1
if [ $nipe_activate -eq 0 ]
then

	# Nipe is not activated. Activate Nipe
	
	echo "Nipe is not activated. Activating nipe..."
	
	sudo perl nipe.pl start
	
	echo "Checking nipe status..."
	
	nipe_activation
	
	
	if [ $nipe_activate -eq 0 ]
	then
		
		# Nipe is not activated.
		
		echo "You are not connected through nipe. We will proceed to exit."
		exit
		
	else
		
		# Nipe is activated.
		
		echo "You are anonymous."
		spoofed_ip=$(get_spoofed_ip)
		echo "Your spoofed IP address is $spoofed_ip"
		
		sleep 2
		spoofed_country=$(get_spoofed_country "$spoofed_ip")
		echo "Your spoofed country is $spoofed_country"
	fi
	
else 

	# Nipe has been activated (before)
	
	echo "You are anonymous."
	spoofed_ip=$(get_spoofed_ip)
	echo "Your spoofed IP address is $spoofed_ip"
	
	sleep 2
	spoofed_country=$(get_spoofed_country "$spoofed_ip")
	echo "Your spoofed country is $spoofed_country"
fi

sleep 5
echo 
echo
echo

# 3. User to specify a domain/URL

echo "Specify a domain or IP address to scan:"
read ip_address

sleep 3
echo
echo
echo

# 4. Connect and scan remote server for open ports

# Check if ssh is activated

function ssh_service()
{
	sudo service ssh status | grep -c "inactive"
}
ssh_status=$(ssh_service)

# If ssh is inactive = 1, if ssh is active = 0
if [ $ssh_status -eq 1 ]
then

	# Make known to the user that ssh is inactive and machine will activate it
	echo "ssh server is inactive. Proceeding to activate ssh"
	sudo service ssh start
	
	# Check ssh status again to make sure it is active.
	ssh_service
	
	if [ $ssh_status -eq 1 ]
	then 
		
		# Make known to user that ssh is active
		echo "ssh server is active."
	
	else 
		
		echo "Please check your servers. Proceeding to exit."
		exit
	fi
	
	
else

	# Make known to user that ssh is active
	echo "ssh server is active."
	
fi

echo
echo
echo




# Function to connect to the remote server and execute a command
ssh_connect_and_execute() 
{
    local remote_ip="$1"
    local user_name="$2"
    local user_pwd="$3"
    local command1="$4"

    sshpass -p "$user_pwd" ssh -o StrictHostKeyChecking=no "$user_name@$remote_ip" "$command1"
}

# Retrieving user's remote connection details
echo "Enter your remote IP address:"
read remote_ip

echo "Enter your username for the remote server:"
read user_name

echo "Enter your password for the remote server:"
read -s user_pwd

# Inside the remote server
# 4.2 Display details of remote server (country, IP, Uptime)

echo
echo
echo "You have successfully connected to the remote server."
echo

# Uptime
remote_uptime=$(ssh_connect_and_execute "$remote_ip" "$user_name" "$user_pwd" "uptime")
echo "Uptime: $remote_uptime"

#ip address
remote_ipadd=$(ssh_connect_and_execute "$remote_ip" "$user_name" "$user_pwd" "hostname -I")
echo "IP address: $remote_ipadd"

# country
echo "$(ssh_connect_and_execute "$remote_ip" "$user_name" "$user_pwd" "whois $remote_ip | grep -i country")"
sleep 5


# Scanning for ports on remote server
echo
echo "Scanning for ports..."
echo
sleep 3

# Define the command (nmap scan) on the remote server and save the results
nmap_command="nmap $ip_address > scan_results.txt"
whois_command="whois $ip_address > whois_scan.txt"

ssh_connect_and_execute "$remote_ip" "$user_name" "$user_pwd" "$nmap_command"
ssh_connect_and_execute "$remote_ip" "$user_name" "$user_pwd" "$whois_command"

# FTP server details
FTP_SERVER="$remote_ip"
FTP_USER="$user_name"
FTP_PASS="$user_pwd"


# Connect to the FTP server and retrieve files
ftp -n $FTP_SERVER <<END_SCRIPT
quote USER $FTP_USER
quote PASS $FTP_PASS
binary
cd /home/$user_name
get scan_results.txt scan_results.txt
get whois_scan.txt whois_scan.txt
quit
END_SCRIPT

echo "File retrieval complete."

sleep 3
echo
echo
echo

# Get current date and time
current_datetime=$(date '+%Y-%m-%d %H:%M:%S')

# Define the log file path
log_file="/var/log/scan_log.txt"

# Log the scan details
echo "Logging the scan details to $log_file"
sleep 2
echo "$current_datetime - Scanned domain/URL: $ip_address" | sudo tee -a "$log_file"
sleep 2
echo "Scan results saved to ~/Desktop/scan_results.txt and ~/Desktop/whois_scan.txt" | sudo tee -a "$log_file"
sleep 2
echo "" | sudo tee -a "$log_file" 


