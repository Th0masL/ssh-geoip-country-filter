# SSH GeoIP Country Filter

## Description

This script is used to be able to detect the country of an IP Address, and return TRUE or FALSE if the country is in the list of allowed countries.

The main purpose of this script is to increase the security of your server by only allowing specific IPs or Countries to log in using SSH.

## How to use

**WARNING :**

**From the moment you edit the file `/etc/hosts.deny` and `/etc/hosts.allow` below, you will have to make sure that you finish the configuration and test that you can login !**

**Do not close your current SSH session before having tested that you can login from a NEW SSH session !**

**You can revert your changes and disable this script by reverting the content of the file `/etc/hosts.deny` and `/etc/hosts.allow`, so remember do to a backup of those two files.**



- Step 1 : Log into the Linux server you want to protect

- Step 2 : Create a folder where you want to store this script

    ```
    mkdir -p /scripts/ssh-geoip-country-filter
    ```

- Step 3 : Clone this GitHub repo into the folder /scripts/ssh-geoip-country-filter

    ```
    git clone --single-branch --branch main https://github.com/Th0masL/ssh-geoip-country-filter.git /scripts/ssh-geoip-country-filter
    ```

- Step 4 : Make the script executable

    ```
    chmod +x /scripts/ssh-geoip-country-filter/ssh-geoip-country-filter.sh
    ````

- Step 5 : Edit the config file and define the IPs and/or Countries Codes to whitelist

    ```
    vim /scripts/ssh-geoip-country-filter/config.ini
    ```

- Step 6 : Make a backup of the file `/etc/hosts.deny` and add the following line to the original one. This line should be the only content of the file.

    ```
    sshd: ALL
    ```

- Step 7 : Make a backup of the file `/etc/hosts.allow` and add the following line to the original one (note presence of the path where the script is located). This line should be the only content of the file.

    ```
    sshd: ALL: aclexec /scripts/ssh-geoip-country-filter/ssh-geoip-country-filter.sh %a
    ```

    IMPORTANT : If you have decided to put the script in another folder, update the path of the script to where the script is located

- Step 8 : You can then run the script manually, and pass some IPs in parameter to test if it is detecting the Whitelist/Country correctly.

    Let's imagine that your current local IP is 192.168.1.132, and that you server is on the same network as you. You will most likely have whitelisted the subnet 192.168.1.0/24, thus whitelisting your local IP at the same time. Let's test it :

    ```
    user@server1:/scripts/ssh-geoip-country-filter/$ ./ssh-geoip-country-filter.sh 192.168.1.132
    <85>Feb  7 20:37:31 user: ALLOW sshd connection from 192.168.1.132 (Whitelisted)
    ```

    Now let's pick an IP from a country you have not allowed. In this example, I will assume that you have not whitelisted the US country, so I can use Google's DNS IP 8.8.8.8 to verify the result is a DENY.

    ```
    user@server1:/scripts/ssh-geoip-country-filter/$ ./ssh-geoip-country-filter.sh 8.8.8.8
    <85>Feb  7 20:37:35 user: DENY sshd connection from 8.8.8.8 (US) - Last Country DB Refresh: 0 days ago (2 minutes ago)
    ```

    You can repeat the test with as many IPs as you want.

- Step 9 : **KEEP THIS EXISTING SSH SESSION OPEN** and open another terminal to open a new SSH session, to confirm if the script is working correctly

- Step 10 : If you were able to login from your new terminal, you should see some logs like that in your /var/log/auth.log file 

    Command to use :

    ```
    user@server1:/# grep "sshd connection" /var/log/auth.log
    ```

    Expected output :

    ```
    Feb  7 20:40:33 server1 root: ALLOW sshd connection from 192.168.1.132 (Whitelisted)
    ```

- And after a while, you should see some logs like that :

    ```
    Feb  7 21:20:27 server1 root: DENY sshd connection from 185.193.88.29 (RU) - Last Country DB Refresh: 0 days ago (72 minutes ago)
    Feb  7 22:10:40 server1 root: DENY sshd connection from 80.82.77.221 (GB) - Last Country DB Refresh: 0 days ago (182 minutes ago)

    ```