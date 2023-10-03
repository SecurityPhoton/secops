#!/bin/bash

# Update the system
echo "Updating the system..."
apt update
apt upgrade -y

# Set up Message of the Day (MotD)
echo "Configuring Message of the Day (MotD)..."
echo "УВАГА!: Несанкціонований доступ заборонено. Ваша діяльність буде відслідкована та зафіксована." > /etc/motd

# SSH Hardening
#echo "Configuring SSH hardening..."
# Backup SSH configuration
#cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
# Disallow root login
#sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
# Allow only specific users to SSH
# Replace 'username' with your username
#echo "AllowUsers username" >> /etc/ssh/sshd_config
# Disable password-based authentication (use key-based authentication)
#sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
# Restart SSH service
#systemctl restart ssh

# Install and configure auditd
echo "Installing auditd..."
apt install auditd -y
echo "                                "
echo " █▀█ █░░█ ███  ░░▀░░█████  ███  "
echo "█░░█ █░░█ █░░█ ░░█░░ ░█░░  █░░█ "
echo "█▀▀█ █░░█ █░░█ ░░█░░ ░█░░  █░░█ "
echo "█░░█ ░██░ ███  ░░█░░ ░█░░▀ ███  "
echo "                                "
# Configure auditd rules (customize as needed)
echo "Configuring auditd rules..."
cat <<EOL > /etc/audit/rules.d/my-audit.rules
# Record attempts to alter system time
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change

# Record system administrator actions (unsuccessful)
-a always,exit -F arch=b32 -S execve -C uid!=0 -F key=admin-actions
-a always,exit -F arch=b64 -S execve -C uid!=0 -F key=admin-actions

## Ignore SELinux AVC records
-a always,exclude -F msgtype=AVC

## Ignore current working directory records
-a always,exclude -F msgtype=CWD

## Cron jobs fill the logs with stuff we normally don't want (works with SELinux)
-a never,user -F subj_type=crond_t
-a never,exit -F subj_type=crond_t

## This prevents chrony from overwhelming the logs
-a never,exit -F arch=b64 -S adjtimex -F auid=-1 -F uid=chrony -F subj_type=chronyd_t

## This is not very interesting and wastes a lot of space if the server is public facing
-a always,exclude -F msgtype=CRYPTO_KEY_USER

## Open VM Tools
-a exit,never -F arch=b64 -S all -F exe=/usr/bin/vmtoolsd
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d -p wa -k sysctl

## Kernel module loading and unloading
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k modules
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k modules
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/rmmod -k modules
-a always,exit -F arch=b64 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules

## Modprobe configuration
-w /etc/modprobe.conf -p wa -k modprobe
-w /etc/modprobe.d -p wa -k modprobe

## KExec usage (all actions)
-a always,exit -F arch=b64 -S kexec_load -k KEXEC

## Special files
-a always,exit -F arch=b64 -S mknod -S mknodat -k specialfiles

## Mount operations (only attributable)
-a always,exit -F arch=b64 -S mount -S umount2 -F auid!=-1 -k mount

-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

## User, group, password databases
-w /etc/group -p wa -k etcgroup
-w /etc/passwd -p wa -k etcpasswd

## Sudoers file changes
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

## Passwd
-w /usr/bin/passwd -p x -k passwd_modification

## Tools to change group identifiers
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /usr/sbin/addgroup -p x -k group_modification
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/adduser -p x -k user_modification

## Login configuration and information
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/log/lastlog -p wa -k login
-w /var/log/tallylog -p wa -k login

### Changes to other files
-w /etc/hosts -p wa -k network_modifications
-w /etc/sysconfig/network -p wa -k network_modifications
-w /etc/sysconfig/network-scripts -p w -k network_modifications
-w /etc/network/ -p wa -k network
-a always,exit -F dir=/etc/NetworkManager/ -F perm=wa -k network_modifications


## System startup scripts
-w /etc/inittab -p wa -k init
-w /etc/init.d/ -p wa -k init
-w /etc/init/ -p wa -k init

## Pam configuration
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/limits.conf -p wa  -k pam
-w /etc/security/limits.d -p wa  -k pam
-w /etc/security/pam_env.conf -p wa -k pam
-w /etc/security/namespace.conf -p wa -k pam
-w /etc/security/namespace.d -p wa -k pam
-w /etc/security/namespace.init -p wa -k pam

## Mail configuration
-w /etc/aliases -p wa -k mail
-w /etc/postfix/ -p wa -k mail
-w /etc/exim4/ -p wa -k mail

## SSH configuration
-w /etc/ssh/sshd_config -k sshd
-w /etc/ssh/sshd_config.d -k sshd

## root ssh key tampering
-w /root/.ssh -p wa -k rootkey


## Process ID change (switching accounts) applications
-w /bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc

## Power state
-w /sbin/shutdown -p x -k power
-w /sbin/poweroff -p x -k power
-w /sbin/reboot -p x -k power
-w /sbin/halt -p x -k power


## Reconnaissance
-w /usr/bin/whoami -p x -k recon
-w /usr/bin/id -p x -k recon
-w /bin/hostname -p x -k recon
-w /bin/uname -p x -k recon
-w /etc/issue -p r -k recon
-w /etc/hostname -p r -k recon

## Suspicious activity
-w /usr/bin/wget -p x -k susp_activity
-w /usr/bin/curl -p x -k susp_activity
-w /usr/bin/base64 -p x -k susp_activity
-w /bin/nc -p x -k susp_activity
-w /bin/netcat -p x -k susp_activity
-w /usr/bin/ncat -p x -k susp_activity
-w /usr/bin/ss -p x -k susp_activity
-w /usr/bin/netstat -p x -k susp_activity
-w /usr/bin/ssh -p x -k susp_activity
-w /usr/bin/scp -p x -k susp_activity
-w /usr/bin/sftp -p x -k susp_activity
-w /usr/bin/ftp -p x -k susp_activity
-w /usr/bin/socat -p x -k susp_activity
-w /usr/bin/wireshark -p x -k susp_activity
-w /usr/bin/tshark -p x -k susp_activity
-w /usr/bin/rawshark -p x -k susp_activity
-w /usr/bin/rdesktop -p x -k susp_activity
-w /usr/local/bin/rdesktop -p x -k susp_activity
-w /usr/bin/wlfreerdp -p x -k susp_activity
-w /usr/bin/xfreerdp -p x -k susp_activity
-w /usr/local/bin/xfreerdp -p x -k susp_activity
-w /usr/bin/nmap -p x -k susp_activity

## Sbin suspicious activity
-w /sbin/iptables -p x -k sbin_susp
-w /sbin/ip6tables -p x -k sbin_susp
-w /sbin/ifconfig -p x -k sbin_susp
-w /usr/sbin/arptables -p x -k sbin_susp
-w /usr/sbin/ebtables -p x -k sbin_susp
-w /sbin/xtables-nft-multi -p x -k sbin_susp
-w /usr/sbin/nft -p x -k sbin_susp
-w /usr/sbin/tcpdump -p x -k sbin_susp
-w /usr/sbin/traceroute -p x -k sbin_susp
-w /usr/sbin/ufw -p x -k sbin_susp

## Suspicious shells
-w /bin/ash -p x -k susp_shell
-w /bin/csh -p x -k susp_shell
-w /bin/fish -p x -k susp_shell
-w /bin/tcsh -p x -k susp_shell
-w /bin/tclsh -p x -k susp_shell
-w /bin/xonsh -p x -k susp_shell
-w /usr/local/bin/xonsh -p x -k susp_shell
-w /bin/open -p x -k susp_shell
-w /bin/rbash -p x -k susp_shell


## Shell/profile configurations
-w /etc/profile.d/ -p wa -k shell_profiles
-w /etc/profile -p wa -k shell_profiles
-w /etc/shells -p wa -k shell_profiles
-w /etc/bashrc -p wa -k shell_profiles
-w /etc/csh.cshrc -p wa -k shell_profiles
-w /etc/csh.login -p wa -k shell_profiles
-w /etc/fish/ -p wa -k shell_profiles
-w /etc/zsh/ -p wa -k shell_profiles

## Anonymous File Creation
### These rules watch the use of memfd_create
### "memfd_create" creates anonymous file and returns a file descriptor to access it
### When combined with "fexecve" can be used to stealthily run binaries in memory without touching disk
-a always,exit -F arch=b64 -S memfd_create -F key=anon_file_create

## Privilege Abuse
### The purpose of this rule is to detect when an admin may be abusing power by looking in user's home dir.
-a always,exit -F dir=/home -F uid=0 -F auid>=1000 -F auid!=-1 -C auid!=obj_uid -k power_abuse

# Socket Creations
# will catch both IPv4 and IPv6

-a always,exit -F arch=b32 -S socket -F a0=2  -k network_socket_created
-a always,exit -F arch=b64 -S socket -F a0=2  -k network_socket_created

-a always,exit -F arch=b32 -S socket -F a0=10 -k network_socket_created
-a always,exit -F arch=b64 -S socket -F a0=10 -k network_socket_created

# DPKG / APT-GET (Debian/Ubuntu)
-w /usr/bin/dpkg -p x -k software_mgmt
-w /usr/bin/apt -p x -k software_mgmt
-w /usr/bin/apt-add-repository -p x -k software_mgmt
-w /usr/bin/apt-get -p x -k software_mgmt
-w /usr/bin/aptitude -p x -k software_mgmt
-w /usr/bin/wajig -p x -k software_mgmt
-w /usr/bin/snap -p x -k software_mgmt


### Unsuccessful Creation
-a always,exit -F arch=b64 -S mkdir,creat,link,symlink,mknod,mknodat,linkat,symlinkat -F exit=-EACCES -k file_creation
-a always,exit -F arch=b64 -S mkdir,link,symlink,mkdirat -F exit=-EPERM -k file_creation

EOL

# Reload auditd configuration
service auditd reload

echo "Creating user 'secadmin'..."
useradd -m -s /bin/bash secadmin
echo "Setting a password for 'secadmin'..."
passwd secadmin
usermod -aG sudo secadmin

# Enable firewall (use ufw or your preferred firewall)
#echo "Enabling firewall..."
#apt install ufw -y
#ufw enable
#ufw default deny incoming
#ufw default allow outgoing
#ufw allow 22/tcp  # Allow SSH
#ufw allow 80/tcp  # Allow HTTP (customize based on your services)
#ufw allow 443/tcp  # Allow HTTPS (customize based on your services)

# Enable automatic security updates
echo "Configuring automatic security updates..."
apt install unattended-upgrades -y
dpkg-reconfigure -plow unattended-upgrades

echo "Security improvements applied. Please review and customize as needed."
