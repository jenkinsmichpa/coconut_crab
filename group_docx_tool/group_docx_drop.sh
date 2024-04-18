#!/bin/bash

# Specify groups to report on here
groups=(1)

share="share"
username=""
password=""

# Verify that required dependency commands are installed and offer to install them if not
dependencyCommands=(nmap smbclient)

for dependencyCommand in "${dependencyCommands[@]}"; do
	if ! command -v "${dependencyCommand}" &> /dev/null; then
		echo "${dependencyCommand} is a dependency of this script."
		if command -v apt &> /dev/null; then
			read -p "Install ${dependencyCommand} now? [y/N] " userInput
			if [[ "${userInput}" == 'y' ]] || [[ "${userInput}" == 'Y' ]]; then
				sudo apt update > /dev/null 2>&1
				sudo apt install "${dependencyCommand}" -y > /dev/null 2>&1
				if [[ ! $? -eq 0 ]]; then
					echo "An installation error has occured."
					exit
				fi
			else
				exit
			fi
		else
			echo "Please install ${dependencyCommand}."
			exit
		fi
	fi
done

for group in "${groups[@]}"; do
    ip_address="10.0.${group}.2"
    local_file=$(ls | grep "Group ${group}") # Get local file matching group number

    scanout=$(sudo nmap -n -Pn -T4 -p 389 "${ip_address}" --script ldap-rootdse) # Pull LDAP service information
    domain=$(echo "${scanout}" | grep dnsHostName | awk -F '.' '{ print $(NF-1) "." $(NF) }') # Extract AD domain from LDAP output

    smbclient "//${ip_address}/${share}" -U "${domain}\\${username}%${password}" -c "put ${local_file} ${local_file}" # Copy local file to remote file share
done
