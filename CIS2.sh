#!/bin/bash
# CIS Benchmark Ubuntu 22.04 LTS
# Autor: Miranda Sosa Jesus Ignacio
touch /etc/modprobe.d/CIS.conf
# CIS Capitulo 1
# CIS security standards 1.1.1.1 to 1.1.1.3
# 1.1.1.1 Ensure mounting of cramfs filesystems is disabled
# 1.1.1.2 Ensure mounting of squashfs filesystems is disabled
# 1.1.1.3 Ensure mounting of udf filesystems is disabled
echo "install cramfs /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf
echo "install squashfs /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf
echo "install udf /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf
# CIS security standards 1.1.2.1 to 1.1.2.4
# 1.1.2.1 Ensure /tmp is a separate partition
# 1.1.2.2 Ensure nodev option set on /tmp partition
# 1.1.2.3 Ensure noexec option set on /tmp partition
# 1.1.2.4 Ensure nosuid option set on /tmp partition
#if ! mount | grep /tmp >/dev/null; then
#  echo "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
#  mount -o remount /tmp
#fi
# Ensure nodev option set on /tmp partition
#if ! mount | grep /tmp | grep nodev >/dev/null; then
#  sed -i 's/\(^.*\/tmp.*$\)/\1,nodev/' /etc/fstab
#  mount -o remount /tmp
#fi
# Ensure noexec option set on /tmp partition
#if ! mount | grep /tmp | grep noexec >/dev/null; then
#  sed -i 's/\(^.*\/tmp.*$\)/\1,noexec/' /etc/fstab
#  mount -o remount /tmp
#fi
# Ensure nosuid option set on /tmp partition
#if ! mount | grep /tmp | grep nosuid >/dev/null; then
#  sed -i 's/\(^.*\/tmp.*$\)/\1,nosuid/' /etc/fstab
#  mount -o remount /tmp
#fi
# Save configuration
echo "options tmpfs size=512M,nr_inodes=50k,mode=1777,uid=0,gid=0,nodev,nosuid,noexec,noatime,discard" > /etc/modprobe.d/CIS.conf
# CIS security standards 1.1.3.1 to 1.1.3.3
# 1.1.3.1 Ensure separate partition exists for /var
# 1.1.3.2 Ensure nodev option set on /var partition
# 1.1.3.3 Ensure nosuid option set on /var partition
#echo "Creating a separate partition for /var..."
#sudo mkdir /varbackup
#sudo cp -Rpf /var/* /varbackup/
#sudo rm -rf /var/*
#echo '/dev/mapper/vg_var-lv_var /var ext4 defaults,nodev,nosuid,noexec 0 0' | sudo tee -a /etc/fstab
#sudo mount -o remount /var
#sudo cp -Rpf /varbackup/* /var/
#sudo rm -rf /varbackup
# Ensure separate partition exists for /var/tmp
#sudo mkdir /var/tmpbackup
#sudo cp -Rpf /var/tmp/* /var/tmpbackup/
#sudo rm -rf /var/tmp/*
#echo '/dev/mapper/vg_var-lv_vartmp /var/tmp ext4 defaults,nodev,nosuid,noexec 0 0' | sudo tee -a /#etc/fstab
#sudo mount -o remount /var/tmp
#sudo cp -Rpf /var/tmpbackup/* /var/tmp/
#sudo rm -rf /var/tmpbackup
# Ensure nosuid option set on /var partition
#echo "tmpfs /var/log tmpfs defaults,nodev,nosuid,noexec 0 0" | sudo tee -a /etc/modprobe.d/CIS.conf
#echo "tmpfs /var/log/audit tmpfs defaults,nodev,nosuid,noexec 0 0" | sudo tee -a /etc/modprobe.d/#CIS.conf
#echo '/dev/mapper/vg_var-lv_var /var ext4 defaults,nodev,nosuid,noexec 0 0' | sudo tee -a /etc/#modprobe.d/CIS.conf
#sudo mount -o remount /var
#echo "options tmpfs nosuid" | sudo tee -a /etc/modprobe.d/CIS.conf
# Ensure nosuid option set on /var/tmp partition
#echo "tmpfs /var/tmp tmpfs defaults,nodev,nosuid,noexec 0 0" | sudo tee -a /etc/modprobe.d/CIS.conf
#echo '/dev/mapper/vg_var-lv_vartmp /var/tmp ext4 defaults,nodev,nosuid,noexec 0 0' | sudo tee -a /#etc/modprobe.d/CIS.conf
#sudo mount -o remount /var/tmp
#echo "options tmpfs nosuid" | sudo tee -a /etc/modprobe.d/CIS.conf
# CIS security standards 1.1.4.1 to 1.1.4.4
# 1.1.4.1 Ensure separate partition exists for /var/tmp
# 1.1.4.2 Ensure nodev option set on /var/tmp partition
# 1.1.4.3 Ensure nosuid option set on /var/tmp partition
# 1.1.4.4 Ensure noexec option set on /var/tmp partition
# Ensure separate partition exists for /var/tmp
if ! grep -q "/var/tmp" /etc/fstab ; then
  echo "tmpfs /var/tmp tmpfs defaults,nosuid,nodev,noexec 0 0" >> /etc/fstab
  mount -o remount,noexec,nodev,nosuid /var/tmp
fi
# Ensure nodev option set on /var/tmp partition
if ! mount | grep -q "/var/tmp.*nodev" ; then
  mount -o remount,nodev /var/tmp
fi
# Ensure nosuid option set on /var/tmp partition
if ! mount | grep -q "/var/tmp.*nosuid" ; then
  mount -o remount,nosuid /var/tmp
fi
# Ensure noexec option set on /var/tmp partition
if ! mount | grep -q "/var/tmp.*noexec" ; then
  mount -o remount,noexec /var/tmp
fi
# Save configuration
echo "tmpfs /var/tmp tmpfs defaults,nosuid,nodev,noexec 0 0" >> /etc/modprobe.d/CIS.conf
echo "/var/tmp    nodev" >> /etc/modprobe.d/CIS.conf
echo "/var/tmp    nosuid" >> /etc/modprobe.d/CIS.conf
echo "/var/tmp    noexec" >> /etc/modprobe.d/CIS.conf
# CIS security standards 1.1.5.1 to 1.1.5.4
# 1.1.5.1 Ensure separate partition exists for /var/log
# 1.1.5.2 Ensure nodev option set on /var/log partition
# 1.1.5.3 Ensure noexec option set on /var/log partition
# 1.1.5.4 Ensure nosuid option set on /var/log partition
# Ensure separate partition exists for /var/log
if ! grep -q "/var/log" /etc/fstab ; then
  echo "/dev/sda2 /var/log ext4 defaults,nodev,nosuid,noexec 0 2" >> /etc/fstab
  mount -o remount,noexec,nodev,nosuid /var/log
fi
# Ensure nodev option set on /var/log partition
if ! mount | grep -q "/var/log.*nodev" ; then
  mount -o remount,nodev /var/log
fi
# Ensure noexec option set on /var/log partition
if ! mount | grep -q "/var/log.*noexec" ; then
  mount -o remount,noexec /var/log
fi
# Ensure nosuid option set on /var/log partition
if ! mount | grep -q "/var/log.*nosuid" ; then
  mount -o remount,nosuid /var/log
fi
# Save configurations
echo "/dev/sda2    /var/log    ext4    defaults,nodev,nosuid,noexec    0    2" >> /etc/modprobe.d/CIS.conf
echo "/var/log    nodev" >> /etc/modprobe.d/CIS.conf
echo "/var/log    noexec" >> /etc/modprobe.d/CIS.conf
echo "/var/log    nosuid" >> /etc/modprobe.d/CIS.conf
# CIS security standards 1.1.6.1 to 1.1.6.4
# 1.1.6.1 Ensure separate partition exists for /var/log/audit
# 1.1.6.2 Ensure nodev option set on /var/log/audit partition
# 1.1.6.3 Ensure noexec option set on /var/log/audit partition
# 1.1.6.4 Ensure nosuid option set on /var/log/audit partition
# Ensure separate partition exists for /var/log/audit
if ! grep -q "/var/log/audit" /etc/fstab ; then
  echo "/dev/sda3 /var/log/audit ext4 defaults,nodev,nosuid,noexec 0 2" >> /etc/fstab
  mount -o remount,noexec,nodev,nosuid /var/log/audit
fi
# Ensure nodev option set on /var/log/audit partition
if ! mount | grep -q "/var/log/audit.*nodev" ; then
  mount -o remount,nodev /var/log/audit
fi
# Ensure noexec option set on /var/log/audit partition
if ! mount | grep -q "/var/log/audit.*noexec" ; then
  mount -o remount,noexec /var/log/audit
fi
# Ensure nosuid option set on /var/log/audit partition
if ! mount | grep -q "/var/log/audit.*nosuid" ; then
  mount -o remount,nosuid /var/log/audit
fi
# Save configurations
echo "/dev/sda3    /var/log/audit    ext4    defaults,nodev,nosuid,noexec    0    2" >> /etc/modprobe.d/CIS.conf
echo "/var/log/audit    nodev" >> /etc/modprobe.d/CIS.conf
echo "/var/log/audit    noexec" >> /etc/modprobe.d/CIS.conf
echo "/var/log/audit    nosuid" >> /etc/modprobe.d/CIS.conf
# CIS security standards 1.1.7.1 to 1.1.7.3
# 1.1.7.1 Ensure separate partition exists for /home
# 1.1.7.2 Ensure nodev option set on /home partition
# 1.1.7.3 Ensure nosuid option set on /home partition
# Ensure separate partition exists for /home
if ! grep -q "^[^#].*\s/home\s" /etc/fstab; then
  echo "Separate partition does not exist for /home, creating..."
  PARTITION=$(df --output=source /home | tail -n 1)
  UUID=$(blkid -o value $PARTITION | head -n 1)
  echo "UUID=$UUID /home ext4 defaults,nodev,nosuid 0 2" >> /etc/fstab
fi
# Ensure nosuid option set on /home partition
if ! mount | grep "on /home " | grep -q "nosuid"; then
  echo "nosuid option is not set on /home partition, setting..."
  sed -i 's/\s/home\s.*$/\t\/home\text4\tdefaults,nodev,nosuid\t0\t2/' /etc/fstab
  mount -o remount,nosuid /home
fi
# Save configurations to CIS.conf
echo "UUID=$UUID /home ext4 defaults,nodev,nosuid 0 2" >> /etc/modprobe.d/CIS.conf
# CIS security standards 1.1.8.1 to 1.1.8.3
# 1.1.8.1 Ensure nodev option set on /dev/shm partition
# 1.1.8.2 Ensure noexec option set on /dev/shm partition
# 1.1.8.3 Ensure nosuid option set on /dev/shm partition
# Ensure nodev option set on /dev/shm partition
if ! mount | grep "on /dev/shm " | grep -q "nodev"; then
  echo "nodev option is not set on /dev/shm partition, setting..."
  sed -i 's/\s\/dev\/shm\s.*$/\ttmpfs\t\t\t\ttmpfs\tnodev,nosuid\t0\t0/' /etc/fstab
  mount -o remount,nodev /dev/shm
fi
# Ensure nosuid option set on /dev/shm partition
if ! mount | grep "on /dev/shm " | grep -q "nosuid"; then
  echo "nosuid option is not set on /dev/shm partition, setting..."
  sed -i 's/\s\/dev\/shm\s.*$/\ttmpfs\t\t\t\ttmpfs\tnodev,nosuid\t0\t0/' /etc/fstab
  mount -o remount,nosuid /dev/shm
fi
# Save configurations
echo "tmpfs /dev/shm tmpfs nodev,nosuid 0 0" >> /etc/modprobe.d/CIS.conf
# CIS security standards 1.3.1 to 1.3.2
# 1.3.1 Ensure AIDE is installed
# 1.3.2 Ensure filesystem integrity is regularly checked
# Ensure AIDE is installed
if ! dpkg -s aide >/dev/null 2>&1; then
  apt-get update
  apt-get install -y aide
fi
# Ensure filesystem integrity is regularly checked
if ! grep -q "/usr/sbin/aide" /etc/crontab; then
  echo "0 5 * * * root /usr/sbin/aide --check" >> /etc/crontab
fi
# Save configurations
echo "install aide /bin/true" >> /etc/modprobe.d/CIS.conf
echo "0 5 * * * root /usr/sbin/aide --check" >> /etc/modprobe.d/CIS.conf
# CIS security standards 1.4.1 to 1.4.3
# 1.4.1 Ensure bootloader password is set
# 1.4.2 Ensure permissions on bootloader config are configured
# 1.4.3 Ensure authentication required for single user mode
# Ensure bootloader password is set
echo "set superuser-password=\"Miranda21\"" >> /etc/grub.d/40_custom
# Ensure permissions on bootloader config are configured
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
# Ensure authentication required for single user mode
sed -i 's/sushell/sushell auth/' /usr/lib/systemd/system/rescue.service
sed -i 's/sushell/sushell auth/' /usr/lib/systemd/system/emergency.service
# Save configurations to CIS.conf
echo "set superuser-password=\"Miranda21\"" >> /etc/modprobe.d/CIS.conf
echo "chown root:root /boot/grub2/grub.cfg" >> /etc/modprobe.d/CIS.conf
echo "chmod og-rwx /boot/grub2/grub.cfg" >> /etc/modprobe.d/CIS.conf
echo "sed -i 's/sushell/sushell auth/' /usr/lib/systemd/system/rescue.service" >> /etc/modprobe.d/CIS.conf
echo "sed -i 's/sushell/sushell auth/' /usr/lib/systemd/system/emergency.service" >> /etc/modprobe.d/CIS.conf
# CIS security standards 1.5.1 to 1.5.3
# 1.5.1 Ensure address space layout randomization (ASLR) is enabled
# 1.5.2 Ensure prelink is not installed
# 1.5.3 Ensure Automatic Error Reporting is not enabled
# 1.5.4 Ensure core dumps are restricted
# Ensure address space layout randomization (ASLR) is enabled
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/60-CIS.conf
# Ensure prelink is not installed
if rpm -q prelink >/dev/null; then
   yum remove -y prelink
fi
# Ensure Automatic Error Reporting is not enabled
systemctl disable abrtd.service
systemctl stop abrtd.service
# Ensure core dumps are restricted
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/60-CIS.conf
echo "kernel.core_uses_pid = 1" >> /etc/sysctl.d/60-CIS.conf
echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.d/60-CIS.conf
# Guardar las configuraciones en CIS.conf
cat /etc/sysctl.d/60-CIS.conf >> /etc/modprobe.d/CIS.conf
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/modprobe.d/CIS.conf
echo "kernel.core_uses_pid = 1" >> /etc/modprobe.d/CIS.conf
echo "kernel.dmesg_restrict = 1" >> /etc/modprobe.d/CIS.conf
# CIS security standards 1.6.1 to 1.6.4
# 1.6.1.1 Ensure AppArmor is installed
# 1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration
# 1.6.1.3 Ensure all AppArmor Profiles are in enforce or complain mode
# 1.6.1.4 Ensure all AppArmor Profiles are enforcing
# Ensure AppArmor is installed (Automated)
apt-get install -y apparmor
echo "security_soft_limit=1024" >> /etc/apparmor/parser.conf
# Ensure AppArmor is enabled in the bootloader configuration (Automated)
sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=\"/GRUB_CMDLINE_LINUX_DEFAULT=\"apparmor=1 security=apparmor /g' /etc/default/grub
update-grub
# Ensure all AppArmor Profiles are in enforce or complain mode (Automated)
aa-enforce /etc/apparmor.d/*
aa-complain /etc/apparmor.d/usr.sbin.rsyslogd
# Ensure all AppArmor Profiles are enforcing (Automated)
sed -i 's/^#include <tunables/global>//g' /etc/apparmor.d/* && \
echo -e 'profile * /usr/bin/ {\n  #include <tunables/global>\n}\n' > /etc/apparmor.d/tunables/global && \
apparmor_parser -r /etc/apparmor.d/*
echo "APPARMOR_MODULES=\"all\"" >> /etc/apparmor.d/tunables/aaa_base
echo "APPARMOR_MODULES=\"all\"" >> /etc/environment
# Save configurations
echo "install apparmor /bin/true" >> /etc/modprobe.d/CIS.conf
echo "security_soft_limit=1024" >> /etc/modprobe.d/CIS.conf
echo 'GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor"' >> /etc/modprobe.d/CIS.conf
echo "aa-enforce /etc/apparmor.d/*" >> /etc/modprobe.d/CIS.conf
echo "aa-complain /etc/apparmor.d/usr.sbin.rsyslogd" >> /etc/modprobe.d/CIS.conf
echo -e 'profile * /usr/bin/ {\n  #include <tunables/global>\n}\n' > /etc/modprobe.d/CIS.conf
echo "APPARMOR_MODULES=\"all\"" >> /etc/modprobe.d/CIS.conf
# CIS security standards 1.7.1 to 1.7.6
# 1.7.1 Ensure message of the day is configured properly
# 1.7.2 Ensure local login warning banner is configured properly
# 1.7.3 Ensure remote login warning banner is configured properly
# 1.7.4 Ensure permissions on /etc/motd are configured
# 1.7.5 Ensure permissions on /etc/issue are configured
# 1.7.6 Ensure permissions on /etc/issue.net are configured
# Ensure message of the day is configured properly (Automated)
echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
chmod 644 /etc/motd
chmod 644 /etc/issue
chmod 644 /etc/issue.net
# CIS security standards 1.8.1 to 1.8.10
# 1.8.1 Ensure GNOME Display Manager is removed
# 1.8.2 Ensure KDE is not installed
# 1.8.3 Ensure X Window System is not installed
# 1.8.4 Ensure Avahi Server is not enabled
# 1.8.5 Ensure CUPS is not enabled
# 1.8.6 Ensure DHCP Server is not enabled
# 1.8.7 Ensure LDAP server is not enabled
# 1.8.9 Ensure DNS Server is not enabled
# 1.8.10 Ensure XDCMP is not enabled
#systemctl disable gdm.service
#apt-get -y purge gdm3
#apt-get -y purge kde-standard kubuntu-desktop
#apt-get -y purge xserver-xorg-core
#systemctl disable avahi-daemon.service
#systemctl disable cups.service
#systemctl disable isc-dhcp-server.service
#systemctl disable slapd.service
#systemctl disable bind9.service
#systemctl disable xdmcp.service
# CIS Capitulo 2
# CIS security standards 2.1.1.1 to 2.1.4.4
# 2.1.1.1 Ensure a single time synchronization daemon is in use 
# 2.1.2.2 Ensure chrony is running as user _chrony
# 2.1.2.3 Ensure chrony is enabled and running
# 2.1.4.1 Ensure ntp access control is configured
# 2.1.4.3 Ensure ntp is running as user ntp
# 2.1.4.4 Ensure ntp is enabled and running
# 2.1.2.2 Ensure chrony is running as user _chrony
# Ensure only one time synchronization daemon is in use
# Check if ntpd service is running
if systemctl is-active --quiet ntpd; then
    echo "ntpd service is running, disabling it and enabling systemd-timesyncd"
    systemctl stop ntpd
    systemctl disable ntpd
    systemctl enable systemd-timesyncd
elif systemctl is-active --quiet chrony; then
    echo "chrony service is running, disabling it and enabling systemd-timesyncd"
    systemctl stop chrony
    systemctl disable chrony
    systemctl enable systemd-timesyncd
else
    echo "Only systemd-timesyncd is running"
fi
# Configure chrony to run as user _chrony
sed -i 's/^#*.*\buser\b.*/user _chrony/' /etc/chrony.conf
# Restart chrony service
systemctl restart chronyd
# Add result to CIS.conf
echo -e "\n# Ensure chrony is running as user _chrony\n$(grep -E '^\s*user\s+_chrony\b' /etc/chrony.conf || echo 'user _chrony not configured in /etc/chrony.conf')" >> /etc/modprobe.d/CIS.conf
# Ensure chrony is enabled and running
# Install chrony if it is not already installed
if ! rpm -q chrony >/dev/null; then
  yum -y install chrony
fi
# Enable and start chrony
systemctl enable chronyd.service
systemctl start chronyd.service
# Verify that chrony is running
if ! systemctl is-active --quiet chronyd.service; then
  echo "ERROR: chronyd is not running"
fi
# Verify that chrony is enabled
if ! systemctl is-enabled --quiet chronyd.service; then
  echo "ERROR: chronyd is not enabled"
fi
# Verify that chrony is running as user _chrony
if ! ps -ef | grep chronyd | grep -q "_chrony"; then
  echo "ERROR: chronyd is not running as user _chrony"
fi
# Save configurations
echo "systemctl enable chronyd.service" >> /etc/modprobe.d/CIS.conf
echo "systemctl start chronyd.service" >> /etc/modprobe.d/CIS.conf
# Ensure ntp access control is configured
echo "restrict default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
# Ensure ntp is running as user ntp (Automated)
#  Ensure ntp is enabled and running (Automated)
# Set the correct ownership for the ntp configuration files
chown ntp:ntp /etc/ntp.conf /etc/ntp.conf.d/
# Set the correct ownership for the ntp drift file
chown ntp:ntp /var/lib/ntp/
# Modify the ntp systemd unit file to run ntp as the ntp user
sed -i 's/^\(ExecStart=\/usr\/sbin\/ntpd -u\)\s*$/\1 ntp:ntp/' /usr/lib/systemd/system/ntp.service
# Reload the systemd daemon
systemctl daemon-reload
# Enable and start the ntp service
systemctl enable ntp.service
systemctl start ntp.service
# Ensure the service is running
if [ $(systemctl is-active ntp.service) == "active" ]; then
  echo "ntp service is running"
else
  echo "ntp service is not running"
fi
# Save configurations
echo "Ensure ntp is running as user ntp - passed" >> /etc/modprobe.d/CIS.conf
echo "Ensure ntp is enabled and running - passed" >> /etc/modprobe.d/CIS.conf
# CIS security standards 2.2.1 to 2.2.16
# 2.2.1 Ensure X Window System is not installed
# 2.2.2 Ensure Avahi Server is not installed
# 2.2.3 Ensure CUPS is not installed
# 2.2.4 Ensure DHCP Server is not installed
# 2.2.5 Ensure LDAP server is not installed
# 2.2.6 Ensure NFS server is not installed
# 2.2.7 Ensure DNS Server is not installed
# 2.2.8 Ensure FTP Server is not installed
# 2.2.9 Ensure HTTP server is not installed
# 2.2.10 Ensure IMAP and POP3 server is not installed
# 2.2.11 Ensure Samba is not installed
# 2.2.12 Ensure HTTP Proxy Server is not installed
# 2.2.13 Ensure SNMP Server is not installed
# 2.2.14 Ensure mail transfer agent is configured for local-only mode
# 2.2.15 Ensure rsync service is not enabled
# 2.2.16 Ensure NIS Server is not installed
# Ensure Avahi Server is not installed
systemctl stop avahi-daaemon.service
systemctl stop avahi-daemon.socket
apt purge avahi-daemon
# Ensure CUPS is not installed
apt-get remove --purge cups -y
# Ensure DHCP Server is not installed
apt-get remove --purge isc-dhcp-server -y
# Ensure LDAP server is not installed
apt-get remove --purge slapd -y
# Ensure NFS server is not installed
apt-get remove --purge nfs-kernel-server -y
# Ensure DNS Server is not installed
apt-get remove --purge bind9 -y
# Ensure FTP Server is not installed
apt-get remove --purge vsftpd -y
# Ensure HTTP server is not installed
apt-get remove --purge apache2 -y
# Ensure IMAP and POP3 server is not installed
apt-get remove --purge dovecot-imapd dovecot-pop3d -y
# Ensure Samba is not installed
apt-get remove --purge samba -y
# Ensure HTTP Proxy Server is not installed
apt-get remove --purge squid -y
# Ensure SNMP Server is not installed
apt-get remove --purge snmpd -y
# Ensure mail transfer agent is configured for local-only mode
sed -i 's/inet_interfaces.*/inet_interfaces = loopback-only/g' /etc/postfix/main.cf
# Ensure rsync service is not enabled
systemctl disable rsync
# Ensure NIS Server is not installed
apt-get remove --purge nis -y
# CIS security standards 2.3.1 to 2.3.6
# 2.3.1 Ensure NIS Client is not installed
# 2.3.2 Ensure rsh client is not installed
# 2.3.3 Ensure talk client is not installed
# 2.3.4 Ensure telnet client is not installed
# 2.3.5 Ensure LDAP client is not installed
# 2.3.6 Ensure RPC is not installed
# Ensure NIS Client is not installed
dpkg -s nis > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "nis package is installed, removing..."
  apt-get remove -y nis
fi
# Ensure rsh client is not installed
dpkg -s rsh-client > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "rsh-client package is installed, removing..."
  apt-get remove -y rsh-client
fi
# Ensure talk client is not installed
dpkg -s talk > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "talk package is installed, removing..."
  apt-get remove -y talk
fi
# Ensure telnet client is not installed
dpkg -s telnet > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "telnet package is installed, removing..."
  apt-get remove -y telnet
fi
# Ensure LDAP client is not installed
dpkg -s ldap-utils > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "ldap-utils package is installed, removing..."
  apt-get remove -y ldap-utils
fi
# Ensure RPC is not installed
dpkg -s rpcbind > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "rpcbind package is installed, removing..."
  apt-get remove -y rpcbind
fi
# Save the results to CIS.conf
echo "Ensure NIS Client is not installed (Automated): $(dpkg -s nis > /dev/null 2>&1; echo $?)" >> /etc/modprobe.d/CIS.conf
echo "Ensure rsh client is not installed (Automated): $(dpkg -s rsh-client > /dev/null 2>&1; echo $?)" >> /etc/modprobe.d/CIS.conf
echo "Ensure talk client is not installed (Automated): $(dpkg -s talk > /dev/null 2>&1; echo $?)" >> /etc/modprobe.d/CIS.conf
echo "Ensure telnet client is not installed (Automated): $(dpkg -s telnet > /dev/null 2>&1; echo $?)" >> /etc/modprobe.d/CIS.conf
echo "Ensure LDAP client is not installed (Automated): $(dpkg -s ldap-utils > /dev/null 2>&1; echo $?)" >> /etc/modprobe.d/CIS.conf
echo "Ensure RPC is not installed (Automated): $(dpkg -s rpcbind > /dev/null 2>&1; echo $?)" >> /etc/modprobe.d/CIS.conf
# CIS Capitulo 3
# CIS security standards 3.1.1
# 3.1.2 Ensure wireless interfaces are disabled
# Ensure wireless interfaces are disabled
for i in $(iwconfig 2>/dev/null | grep "IEEE 802.11" | awk '{print $1}'); do
    echo "Setting $i to down"
    ip link set $i down
done
# Add to CIS.conf
echo -e "\n# Ensure wireless interfaces are disabled" >> /etc/modprobe.d/CIS.conf
echo "for i in \$(iwconfig 2>/dev/null | grep "IEEE 802.11" | awk '{print \$1}'); do" >> /etc/modprobe.d/CIS.conf
echo -e "\techo \"Setting \$i to down\"" >> /etc/modprobe.d/CIS.conf
echo -e "\tip link set \$i down" >> /etc/modprobe.d/CIS.conf
echo "done" >> /etc/modprobe.d/CIS.conf
# CIS security standards 3.2.1 to 3.2.2
# 3.2.1	Ensure packet redirect sending is disabled		
# 3.2.2	Ensure IP forwarding is disabled
# Ensure packet redirect sending is disabled
echo "net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects=0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
echo -e "\n# Ensure packet redirect sending is disabled" >> /etc/modprobe.d/CIS.conf
cat /etc/sysctl.conf >> CIS.conf
# Ensure IP forwarding is disabled
echo "# Ensure IP forwarding is disabled " >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv6.conf.default.forwarding = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv6.conf.lo.forwarding = 0" >> /etc/sysctl.d/CIS.conf
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.conf.all.forwarding=0
sysctl -w net.ipv6.conf.default.forwarding=0
sysctl -w net.ipv6.conf.lo.forwarding=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
# CIS security standards 3.3.1 to 3.3.9	
# 3.3.1 Ensure source routed packets are not accepted
# 3.3.2 Ensure ICMP redirects are not accepted
# 3.3.3 Ensure secure ICMP redirects are not accepted	
# 3.3.4 Ensure suspicious packets are logged
# 3.3.5 Ensure broadcast ICMP requests are ignored
# 3.3.6 Ensure bogus ICMP responses are ignored
# 3.3.7 Ensure Reverse Path Filtering is enabled
# 3.3.8 Ensure TCP SYN Cookies is enabled
# 3.3.9 Ensure IPv6 router advertisements are not accepted
# Ensure source routed packets are not accepted
echo "# Ensure source routed packets are not accepted" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
echo "Configuration complete. Please restart the network service or reboot the system for changes to take effect."
# Ensure ICMP redirects are not accepted (Automated)
echo "# Ensure ICMP redirects are not accepted (Automated)" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
# Ensure secure ICMP redirects are not accepted
if grep -q "^net.ipv4.conf.all.secure_redirects" /etc/sysctl.conf; then
  sed -i "s/^net.ipv4.conf.all.secure_redirects.*/net.ipv4.conf.all.secure_redirects = 0/" /etc/sysctl.conf
else
  echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
fi
if grep -q "^net.ipv4.conf.default.secure_redirects" /etc/sysctl.conf; then
  sed -i "s/^net.ipv4.conf.default.secure_redirects.*/net.ipv4.conf.default.secure_redirects = 0/" /etc/sysctl.conf
else
  echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
fi
if grep -q "^net.ipv4.conf.all.accept_redirects" /etc/sysctl.conf; then
  sed -i "s/^net.ipv4.conf.all.accept_redirects.*/net.ipv4.conf.all.accept_redirects = 0/" /etc/sysctl.conf
else
  echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
fi
if grep -q "^net.ipv4.conf.default.accept_redirects" /etc/sysctl.conf; then
  sed -i "s/^net.ipv4.conf.default.accept_redirects.*/net.ipv4.conf.default.accept_redirects = 0/" /etc/sysctl.conf
else
  echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
fi
# Load new kernel parameters
sysctl -p
# Save configuration to CIS.conf
echo -e "\n# Ensure secure ICMP redirects are not accepted\nnet.ipv4.conf.all.secure_redirects = 0\nnet.ipv4.conf.default.secure_redirects = 0\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0\n" >> CIS.conf
# Ensure broadcast ICMP requests are ignored
echo "# Ensure broadcast ICMP requests are ignored (Automated)" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
# Ensure bogus ICMP responses are ignored
echo "# Ensure bogus ICMP responses are ignored" >> /etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
# Ensure Reverse Path Filtering is enabled 
echo "# Ensure Reverse Path Filtering is enabled" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
# Ensure TCP SYN Cookies is enabled
echo "# Ensure TCP SYN Cookies is enabled" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sysctl -p
# Ensure IPv6 router advertisements are not accepted
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
# Add settings to sysctl.conf file
echo -e "\n# Disable IPv6 Router Advertisements\nnet.ipv6.conf.all.accept_ra = 0\nnet.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
# Reload sysctl configuration
sysctl -p
# Save settings to CIS configuration file
echo "net.ipv6.conf.all.accept_ra=0" >> /etc/modprobe.d/CIS.conf
echo "net.ipv6.conf.default.accept_ra=0" >> /etc/modprobe.d/CIS.conf
# Ensure IPv6 router advertisements are not accepted
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
# Add settings to sysctl.conf file
echo -e "\n# Disable IPv6 Router Advertisements\nnet.ipv6.conf.all.accept_ra = 0\nnet.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
# Reload sysctl configuration
sysctl -p
# Save settings to CIS configuration file
echo "net.ipv6.conf.all.accept_ra=0" >> /etc/modprobe.d/CIS.conf
echo "net.ipv6.conf.default.accept_ra=0" >> /etc/modprobe.d/CIS.conf
# CIS security standards 3.4.1 to 3.4.4	
# 3.4.1	Ensure DCCP is disabled	
# 3.4.2	Ensure SCTP is disabled		
# 3.4.3	Ensure RDS is disabled		
# 3.4.4	Ensure TIPC is disabled
echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
# CIS security standards 3.5.1.1 to 3.5.1.7
# 3.5.1.1 Ensure ufw is installed	
# 3.5.1.2 Ensure iptables-persistent is not installed with ufw	
# 3.5.1.3 Ensure ufw service is enabled
# 3.5.1.4 Ensure ufw loopback traffic is configured
# 3.5.1.5 Ensure ufw outbound connections are configured
# 3.5.1.6 Ensure ufw firewall rules exist for all open ports
# 3.5.1.7 Ensure ufw default deny firewall policy
# Ensure ufw is installed
apt-get install ufw
apt-get remove -y iptables-persistent
systemctl enable ufw
ufw allow in on lo
ufw allow out on lo
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
ufw default deny incoming
ufw default deny outgoing

# CIS security standards 3.5.2.1 to 3.5.2.10		
# 3.5.2.1 Ensure nftables is installed
# 3.5.2.2 Ensure ufw is uninstalled or disabled with nftables
# 3.5.2.4 Ensure a nftables table exists
# 3.5.2.5 Ensure nftables base chains exist	
# 3.5.2.6 Ensure nftables loopback traffic is configured		
# 3.5.2.8 Ensure nftables default deny firewall policy
# 3.5.2.9 Ensure nftables service is enabled
# 3.5.2.10 Ensure nftables rules are permanent
# Ensure nftables is installed
apt-get install nftables -y
# Ensure ufw is uninstalled or disabled with nftables
apt-get remove ufw -y
ufw disable
# Ensure a nftables table exists
nft add table inet filter
# Ensure nftables base chains exist
nft add chain inet filter input { type filter hook input priority 0 \; }
nft add chain inet filter output { type filter hook output priority 0 \; }
nft add chain inet filter forward { type filter hook forward priority 0 \; }
# Ensure nftables loopback traffic is configured
nft add rule inet filter input iif lo accept
nft add rule inet filter output oif lo accept
# Ensure nftables default deny firewall policy
nft add rule inet filter input drop
nft add rule inet filter forward drop
nft add rule inet filter output accept
# Ensure nftables service is enabled
systemctl enable nftables
# Ensure nftables rules are permanent
nft list ruleset > /etc/nftables.conf
# CIS security standards 3.5.3.1 to 3.5.3.1.3	
# 3.5.3.1.1	Ensure iptables packages are installed
# 3.5.3.1.2	Ensure nftables is not installed with iptables
# 3.5.3.1.3	Ensure ufw is uninstalled or disabled with iptables
# Ensure iptables packages are installed
echo "Checking if iptables package is installed..."
if ! dpkg -s iptables >/dev/null 2>&1; then
    echo "iptables package is not installed. Installing..."
    apt-get install -y iptables
    echo "iptables package installed."
fi
# Ensure nftables is not installed with iptables
echo "Checking if nftables is installed along with iptables..."
if dpkg -s nftables >/dev/null 2>&1; then
    echo "nftables package is installed along with iptables. Removing..."
    apt-get remove -y nftables
    echo "nftables package removed."
fi
# Ensure ufw is uninstalled or disabled with iptables
echo "Checking if ufw is installed or enabled with iptables..."
if systemctl is-enabled ufw >/dev/null 2>&1 || dpkg -s ufw >/dev/null 2>&1; then
    echo "ufw is enabled or installed with iptables. Disabling and removing..."
    systemctl disable ufw
    apt-get remove -y ufw
    echo "ufw disabled and removed."
fi
echo "iptables configuration completed." >> /etc/modprobe.d/CIS.conf
# CIS security standards 3.5.3.2 to 3.5.3.2.4			
# 3.5.3.2.1	Ensure iptables default deny firewall policy
# 3.5.3.2.2	Ensure iptables loopback traffic is configured
# 3.5.3.2.4	Ensure iptables firewall rules exist for all open ports	
# Ensure iptables default deny firewall policy
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
# Ensure iptables loopback traffic is configured
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
# Ensure iptables firewall rules exist for all open ports
# Replace <port_number> with the actual port number you want to open
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
# CIS security standards 3.5.3.3.1 to 3.5.3.3.4
# 3.5.3.3.1	Ensure ip6tables default deny firewall policy		
# 3.5.3.3.2	Ensure ip6tables loopback traffic is configured
# 3.5.3.3.4	Ensure ip6tables firewall rules exist for all open ports
# Ensure ip6tables default deny firewall policy
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
# Ensure ip6tables loopback traffic is configured
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
# Ensure ip6tables firewall rules exist for all open ports
open_ports=$(ss -tln6 | awk 'NR>1 {gsub(/.*:/,"",$4); print $4}')
for port in $open_ports; do
    ip6tables -A INPUT -p tcp --dport $port -j ACCEPT
done
# CIS Capitulo 4
# CIS security standards 4.1.1 to 4.1.1.4	
# 4.1.1	Ensure auditing is enabled		
# 4.1.1.1 Ensure auditd is installed
# 4.1.1.2 Ensure auditd service is enabled and active
# 4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled
# 4.1.1.4 Ensure audit_backlog_limit is sufficient
# Ensure auditd is installed
sudo apt-get install auditd -y
# Ensure auditd service is enabled and active
sudo systemctl enable auditd.service
sudo systemctl start auditd.service
# Ensure auditing for processes that start prior to auditd is enabled
echo "-e 2" >> /etc/default/grub
sudo update-grub
# Ensure audit_backlog_limit is sufficient
echo "GRUB_CMDLINE_LINUX_DEFAULT=\"audit_backlog_limit=8192\"" >> /etc/default/grub
sudo update-grub
# CIS security standards 4.1.2.1 to 4.1.2.3	
# 4.1.2.1 Ensure audit log storage size is configured	
# 4.1.2.2 Ensure audit logs are not automatically deleted	
# 4.1.2.3 Ensure system is disabled when audit logs are full
# Ensure audit log storage size is configured
sed -i 's/^max_log_file .*/max_log_file = 50/g' /etc/audit/auditd.conf
# Ensure audit logs are not automatically deleted
sed -i 's/^max_log_file_action .*/max_log_file_action = keep_logs/g' /etc/audit/auditd.conf
# Ensure system is disabled when audit logs are full
sed -i 's/^space_left_action .*/space_left_action = email/g' /etc/audit/auditd.conf
sed -i 's/^action_mail_acct .*/action_mail_acct = root/g' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action .*/admin_space_left_action = halt/g' /etc/audit/auditd.conf
# CIS security standards 4.1.3.1 to 4.1.3.21
# 4.1.3.1 Ensure changes to system administration scope (sudoers) is collected
# 4.1.3.2 Ensure actions as another user are always logged
# 4.1.3.3 Ensure events that modify the sudo log file are collected
# 4.1.3.4 Ensure events that modify date and time information are collected	
# 4.1.3.5 Ensure events that modify the systems network environment are collected	
# 4.1.3.6 Ensure use of privileged commands are collected
# 4.1.3.7 Ensure unsuccessful file access attempts are collected
# 4.1.3.8 Ensure events that modify user/group information are collected
# 4.1.3.9 Ensure discretionary access control permission modification events are collected
# 4.1.3.10 Ensure successful file system mounts are collected
# 4.1.3.11 Ensure session initiation information is collected
# 4.1.3.12 Ensure login and logout events are collected
# 4.1.3.13 Ensure file deletion events by users are collected
# 4.1.3.14 Ensure events that modify the system Mandatory Access Controls are collected
# 4.1.3.15 Ensure successful and unsuccessful attempts to use the chcon command are recorded
# 4.1.3.16 Ensure successful and unsuccessful attempts to use the setfacl command are recorded		
# 4.1.3.17 Ensure successful and unsuccessful attempts to use the chacl command are recorded	
# 4.1.3.18 Ensure successful and unsuccessful attempts to use the usermod command are recorded		
# 4.1.3.19 Ensure kernel module loading unloading and modification is collected
# 4.1.3.20 Ensure the audit configuration is immutable
# Ensure changes to system administration scope (sudoers) is collected
#echo 'sudoers' >> /etc/audit/rules.d/audit.rules
# Ensure actions as another user are always logged
#echo '-a always,exit -F arch=b64 -S setresuid,setresgid -F auid>=1000 -F auid!=-1 -k privileged-#identity' >> /etc/audit/rules.d/audit.rules
#echo '-a always,exit -F arch=b32 -S setresuid,setresgid -F auid>=1000 -F auid!=-1 -k privileged-#identity' >> /etc/audit/rules.d/audit.rules
# Ensure events that modify the sudo log file are collected
#echo '-w /var/log/sudo.log -p wa -k actions' >> /etc/audit/rules.d/audit.rules
# Ensure events that modify date and time information are collected
#echo '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time-change' >> /#etc/audit/rules.d/audit.rules
#echo '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time-change' >> /#etc/audit/rules.d/audit.rules
#echo '-w /etc/localtime -p wa -k time-change' >> /etc/audit/rules.d/audit.rules
# Ensure events that modify the systems network environment are collected
#echo '-w /etc/issue -p wa -k system-locale' >> /etc/audit/rules.d/audit.rules
#echo '-w /etc/issue.net -p wa -k system-locale' >> /etc/audit/rules.d/audit.rules
#echo '-w /etc/hosts -p wa -k system-locale' >> /etc/audit/rules.d/audit.rules
#echo '-w /etc/network -p wa -k network-config' >> /etc/audit/rules.d/audit.rules
#echo '-w /etc/network/interfaces -p wa -k network-config' >> /etc/audit/rules.d/audit.rules
#echo '-w /etc/resolv.conf -p wa -k network-config' >> /etc/audit/rules.d/audit.rules
# Ensure use of privileged commands are collected
#echo '-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k #privileged-priv_change' >> /etc/audit/rules.d/audit.rules
#echo '-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k #privileged-priv_change' >> /etc/audit/rules.d/audit.rules
#echo '-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k #privileged-priv_change' >> /etc/audit/rules.d/audit.rules
#echo '-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k #privileged-priv_change' >> /etc/audit/rules.d/audit.rules
# Ensure unsuccessful file access attempts are collected
#-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F success=0 -
#F auid>=1000 -F auid!=4294967295 -k access
# Ensure events that modify user/group information are collected
#-w /etc/group -p wa -k identity
#-w /etc/passwd -p wa -k identity
#-w /etc/gshadow -p wa -k identity
#-w /etc/shadow -p wa -k identity
#-w /etc/security/opasswd -p wa -k identity
# Ensure discretionary access control permission modification events are collected
#-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
#-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k #perm_mod
#-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F #auid>=1000 -F auid!=4294967295 -k perm_mod
# Ensure successful file system mounts are collected
#-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
# Ensure successful file system mounts are collected
#sudo echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /#etc/#audit/rules.d/audit.rules
#sudo echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /#etc/audit/rules.d/audit.rules
# Ensure session initiation information is collected
#sudo echo "-w /var/run/utmp -p wa -k sessioninit" >> /etc/audit/rules.d/audit.rules
#sudo echo "-w /var/log/wtmp -p wa -k sessioninit" >> /etc/audit/rules.d/audit.rules
#sudo echo "-w /var/log/btmp -p wa -k sessioninit" >> /etc/audit/rules.d/audit.rules
# Ensure login and logout events are collected
#sudo echo "-w /var/log/auth.log -p wa -k logins" >> /etc/audit/rules.d/audit.rules
#sudo echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
# Ensure file deletion events by users are collected
#sudo echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F #auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
#sudo echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F #auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
# Ensure events that modify the system Mandatory Access Controls are collected
#sudo echo "-w /etc/apparmor/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules
#sudo echo "-w /etc/apparmor.d/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules
# Ensure successful and unsuccessful attempts to use the chcon command are recorded
#sudo echo "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k #perm_chng" >> /etc/audit/rules.d/audit.rules
# successful and unsuccessful attempts to use the setfacl command are recorded
#echo '-a always,exit -F arch=b64 -S setfacl -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/#audit/rules.d/audit.rules
#echo '-a always,exit -F arch=b32 -S setfacl -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/#audit/rules.d/audit.rules
# Ensure successful and unsuccessful attempts to use the chacl command are recorded
#echo '-a always,exit -F arch=b64 -S chacl -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/#audit/rules.d/audit.rules
#echo '-a always,exit -F arch=b32 -S chacl -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/#audit/rules.d/audit.rules
# Ensure successful and unsuccessful attempts to use the usermod command are recorded
#echo '-a always,exit -F arch=b64 -S usermod -F auid>=1000 -F auid!=4294967295 -k user_mod' >> /etc/#audit/rules.d/audit.rules
#echo '-a always,exit -F arch=b32 -S usermod -F auid>=1000 -F auid!=4294967295 -k user_mod' >> /etc/#audit/rules.d/audit.rules
# Ensure kernel module loading unloading and modification is collected
#echo '-w /sbin/insmod -p x -k modules' >> /etc/audit/rules.d/audit.rules
#echo '-w /sbin/rmmod -p x -k modules' >> /etc/audit/rules.d/audit.rules
#echo '-w /sbin/modprobe -p x -k modules' >> /etc/audit/rules.d/audit.rules
#echo '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules' >> /etc/audit/rules.d/#audit.rules
# Ensure the audit configuration is immutable
#echo '-e 2' >> /etc/audit/rules.d/audit.rules
#chattr +a /etc/audit/rules.d/audit.rules
#systemctl restart auditd.service
# CIS security standards 4.1.4.1 to 4.1.4.10	
# 4.1.4.1 Ensure audit log files are mode 0640 or less permissive
# 4.1.4.2Ensure only authorized users own audit log files
# 4.1.4.3 Ensure only authorized groups are assigned ownership of audit log files
# 4.1.4.4 Ensure the audit log directory is 0750 or more restrictive	
# 4.1.4.5 Ensure audit configuration files are 640 or more restrictive
# 4.1.4.6 Ensure audit configuration files are owned by root
# 4.1.4.7 Ensure audit configuration files belong to group root
# 4.1.4.8 Ensure audit tools are 755 or more restrictive	
# 4.1.4.9 Ensure audit tools are owned by root
# 4.1.4.10 Ensure audit tools belong to group root
# Ensure audit log files are mode 0640 or less permissive
echo '-a always,exit -F arch=b64 -F auid>=1000 -F auid!=-1 -F dir=/var/log/audit/ -F perm=wa -F key=audit-wazuh' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -F auid>=1000 -F auid!=-1 -F dir=/var/log/audit/ -F perm=wa -F key=audit-wazuh' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -F auid=0 -F dir=/var/log/audit/ -F perm=wa -F key=audit-wazuh' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -F auid=0 -F dir=/var/log/audit/ -F perm=wa -F key=audit-wazuh' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=audit-wazuh' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=audit-wazuh' >> /etc/audit/rules.d/audit.rules
chmod 0640 /var/log/audit/audit.log
# Ensure only authorized users own audit log files
chown root:root /var/log/audit
# Ensure only authorized groups are assigned ownership of audit log files
chown :adm /var/log/audit/audit.log
chown :adm /var/log/audit/audit.log.1
chown :adm /var/log/audit/audit.log.2
chown :adm /var/log/audit/audit.log.3
chown :adm /var/log/audit/audit.log.4
chown :adm /var/log/audit/audit.log.5
chown :adm /var/log/audit/audit.log.6
chown :adm /var/log/audit/audit.log.7
# Ensure the audit log directory is 0750 or more restrictive
chmod 0750 /var/log/audit
# Ensure audit configuration files are 640 or more restrictive
chmod 640 /etc/audit/rules.d/audit.rules
# Ensure audit configuration files are owned by root
sudo chown root /etc/audit/auditd.conf /etc/audit/audit.rules /etc/audit/rules.d/*
# Ensure audit configuration files belong to group root
sudo chgrp root /etc/audit/auditd.conf /etc/audit/audit.rules /etc/audit/rules.d/*
# Ensure audit tools are 755 or more restrictive
sudo chmod 755 /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/audispd /sbin/augenrules
# Ensure audit tools are owned by root
sudo chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/audispd /sbin/augenrules
# Ensure audit tools belong to group root
sudo chgrp root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/audispd /sbin/augenrules
# CIS security standards 4.2.1.1 to 4.2.1.1.4
# 4.2.1.1 Ensure journald is configured to send logs to a remote log host
# 4.2.1.1.1 Ensure systemd-journal-remote is installed
# 4.2.1.1.4	Ensure journald is not configured to recieve logs from a remote client
# Ensure journald is configured to send logs to a remote log host
# Ensure systemd-journal-remote is installed
# Install the systemd-journal-remote package
apt-get install -y systemd-journal-remote
# Ensure journald is not configured to recieve logs from a remote client
# Disable remote logging in journald.conf
sed -i 's/#ForwardToSyslog=yes/ForwardToSyslog=no/' /etc/systemd/journald.conf
sed -i 's/#ForwardToWall=yes/ForwardToWall=no/' /etc/systemd/journald.conf
# CIS security standards 4.2.1.2 to 4.2.1.4		
# 4.2.1.2 Ensure journald service is enabled
# 4.2.1.3 Ensure journald is configured to compress large log files
# 4.2.1.4 Ensure journald is configured to write logfiles to persistent disk
# Ensure journald service is enabled
systemctl enable systemd-journald.service
# Ensure journald is configured to compress large log files
echo "Compress=yes" >> /etc/systemd/journald.conf
# Ensure journald is configured to write logfiles to persistent disk
echo "Storage=persistent" >> /etc/systemd/journald.conf
# CIS security standards 4.2.2.1 to 4.2.2.7	
# 4.2.2.1 Ensure rsyslog is installed
# 4.2.2.2 Ensure rsyslog service is enabled	
# 4.2.2.4 Ensure rsyslog default file permissions are configured 	
# 4.2.2.7 Ensure rsyslog is not configured to receive logs from a remote client
# Ensure rsyslog is installed
if ! dpkg -s rsyslog >/dev/null 2>&1; then
  echo "rsyslog is not installed. Installing rsyslog..."
  apt-get install -y rsyslog
fi
# Ensure rsyslog service is enabled
if ! systemctl is-enabled rsyslog >/dev/null 2>&1; then
  echo "rsyslog service is not enabled. Enabling rsyslog service..."
  systemctl enable rsyslog
fi
# Ensure rsyslog default file permissions are configured
if ! grep -q "^\$FileCreateMode " /etc/rsyslog.conf; then
  echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf
else
  sed -i "s/^\(\$FileCreateMode \).*/\1 0640/" /etc/rsyslog.conf
fi
# Ensure rsyslog is not configured to receive logs from a remote client
if grep -q "^*.*[^I][^I]*@" /etc/rsyslog.conf; then
  echo "rsyslog is configured to receive logs from a remote client. Removing configuration..."
  sed -i '/^*.*[^I][^I]*@/d' /etc/rsyslog.conf
fi
# Restart rsyslog service to apply changes
systemctl restart rsyslog
# CIS security standards 4.2.3	
# 4.2.3	Ensure all logfiles have appropriate permissions and ownership
# Set a default file permission value
DEFAULT_FILE_PERMISSIONS="640"
# Set a default directory permission value
DEFAULT_DIRECTORY_PERMISSIONS="750"
# Set a default log file owner
DEFAULT_LOG_FILE_OWNER="root:root"
# Set the log directory path
LOG_DIR="/var/log"
# Find all files under the log directory path and set their permissions and ownership
find "$LOG_DIR" -type f -exec chmod "$DEFAULT_FILE_PERMISSIONS" {} \;
find "$LOG_DIR" -type f -exec chown "$DEFAULT_LOG_FILE_OWNER" {} \;
# Find all directories under the log directory path and set their permissions and ownership
find "$LOG_DIR" -type d -exec chmod "$DEFAULT_DIRECTORY_PERMISSIONS" {} \;
find "$LOG_DIR" -type d -exec chown "$DEFAULT_LOG_FILE_OWNER" {} \;
# CIS Capitulo 5
# CIS security standards 5.1.1 to 5.1.9
#5.1.1	Ensure cron daemon is enabled and running	
#5.1.2	Ensure permissions on /etc/crontab are configured	
#5.1.3	Ensure permissions on /etc/cron.hourly are configured	
#5.1.4	Ensure permissions on /etc/cron.daily are configured
#5.1.5	Ensure permissions on /etc/cron.weekly are configured
#5.1.6	Ensure permissions on /etc/cron.monthly are configured
#5.1.7	Ensure permissions on /etc/cron.d are configured
#5.1.8	Ensure cron is restricted to authorized users
#5.1.9	Ensure at is restricted to authorized users
#  Ensure cron daemon is enabled and running
systemctl enable cron
systemctl start cron
# Ensure permissions on /etc/crontab are configured
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
# Ensure permissions on /etc/cron.hourly are configured
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
# Ensure permissions on /etc/cron.daily are configured
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
# Ensure permissions on /etc/cron.weekly are configured
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
# Ensure permissions on /etc/cron.monthly are configured
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
# Ensure permissions on /etc/cron.d are configured
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
# Ensure cron is restricted to authorized users
echo "root" > /etc/cron.allow
echo "user1" >> /etc/cron.allow
echo "user2" >> /etc/cron.allow
chown root:root /etc/cron.allow
chmod 644 /etc/cron.allow
# Ensure at is restricted to authorized users
echo "root" > /etc/at.allow
echo "user1" >> /etc/at.allow
echo "user2" >> /etc/at.allow
chown root:root /etc/at.allow
chmod 644 /etc/at.allow
# CIS security standards 5.2.1 to 5.2.11			
# 5.2.1	Ensure permissions on /etc/ssh/sshd_config are configured	
# 5.2.2	Ensure permissions on SSH private host key files are configured
# 5.2.3	Ensure permissions on SSH public host key files are configured
# 5.2.4	Ensure SSH access is limited
# 5.2.5	Ensure SSH LogLevel is appropriate
# 5.2.6	Ensure SSH PAM is enabled
# 5.2.7	Ensure SSH root login is disabled	
# 5.2.8	Ensure SSH HostbasedAuthentication is disabled
# 5.2.9	Ensure SSH PermitEmptyPasswords is disabled
# 5.2.10 Ensure SSH PermitUserEnvironment is disabled
# 5.2.11 Ensure SSH IgnoreRhosts is enabled
# Ensure permissions on /etc/ssh/sshd_config are configured
#chmod 600 /etc/ssh/sshd_config
# Ensure permissions on SSH private host key files are configured
#chmod 600 /etc/ssh/ssh_host_rsa_key
#chmod 600 /etc/ssh/ssh_host_ecdsa_key
#chmod 600 /etc/ssh/ssh_host_ed25519_key
# Ensure permissions on SSH public host key files are configured
#chmod 644 /etc/ssh/ssh_host_rsa_key.pub
#chmod 644 /etc/ssh/ssh_host_ecdsa_key.pub
#chmod 644 /etc/ssh/ssh_host_ed25519_key.pub
# Ensure SSH access is limited
echo "AllowUsers <username1> <username2>" >> /etc/ssh/sshd_config
echo "AllowGroups <group1> <group2>" >> /etc/ssh/sshd_config
echo "DenyUsers <username3> <username4>" >> /etc/ssh/sshd_config
echo "DenyGroups <group3> <group4>" >> /etc/ssh/sshd_config
# Ensure SSH LogLevel is appropriate
echo "LogLevel INFO" >> /etc/ssh/sshd_config
# Ensure SSH PAM is enabled
sed -i 's/#UsePAM yes/UsePAM yes/g' /etc/ssh/sshd_config
# Ensure SSH root login is disabled
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
# Ensure SSH HostbasedAuthentication is disabled
sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/g' /etc/ssh/sshd_config
# Ensure SSH PermitEmptyPasswords is disabled
sed -i 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
# Ensure SSH PermitUserEnvironment is disabled
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config
# Ensure SSH IgnoreRhosts is enabled
echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
# CIS security standards 5.2.12 to 5.2.22
# 5.2.12 Ensure SSH X11 forwarding is disabled
# 5.2.13 Ensure only strong Ciphers are used
# 5.2.14 Ensure only strong MAC algorithms are used
# 5.2.15 Ensure only strong Key Exchange algorithms are used
# 5.2.16 Ensure SSH AllowTcpForwarding is disabled
# 5.2.17 Ensure SSH warning banner is configured
# 5.2.18 Ensure SSH MaxAuthTries is set to 4 or less
# 5.2.19 Ensure SSH MaxStartups is configured	
# 5.2.20 Ensure SSH MaxSessions is set to 10 or less 	
# 5.2.21 Ensure SSH LoginGraceTime is set to one minute or less
# 5.2.22 Ensure SSH Idle Timeout Interval is configured 
# Ensure SSH X11 forwarding is disabled
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
# Ensure only strong Ciphers are used
echo 'Ciphers aes256-ctr,aes192-ctr,aes128-ctr' >> /etc/ssh/sshd_config
# Ensure only strong MAC algorithms are used
echo 'MACs hmac-sha2-512,hmac-sha2-256' >> /etc/ssh/sshd_config
# Ensure only strong Key Exchange algorithms are used
echo 'KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group14-sha256' >> /etc/ssh/sshd_config
# Ensure SSH AllowTcpForwarding is disabled
sed -i 's/AllowTcpForwarding yes/AllowTcpForwarding no/g' /etc/ssh/sshd_config
# Ensure SSH warning banner is configured
echo 'Banner /etc/issue.net' >> /etc/ssh/sshd_config
# Ensure SSH MaxAuthTries is set to 4 or less
sed -i 's/MaxAuthTries.*/MaxAuthTries 4/g' /etc/ssh/sshd_config
# Ensure SSH MaxStartups is configured
echo 'MaxStartups 10:30:60' >> /etc/ssh/sshd_config
# Ensure SSH MaxSessions is set to 10 or less
sed -i 's/MaxSessions.*/MaxSessions 10/g' /etc/ssh/sshd_config
# Ensure SSH LoginGraceTime is set to one minute or less
sed -i 's/LoginGraceTime.*/LoginGraceTime 1m/g' /etc/ssh/sshd_config
# Ensure SSH Idle Timeout Interval is configured
echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config
echo 'ClientAliveCountMax 0' >> /etc/ssh/sshd_config
# Restart SSH service to apply changes
systemctl restart sshd
# CIS security standards 5.3.1 to 5.3.7				
# 5.3.1	Ensure sudo is installed		
# 5.3.2	Ensure sudo commands use pty	
# 5.3.3	Ensure sudo log file exists
# 5.3.4	Ensure users must provide password for privilege escalation
# 5.3.5	Ensure re-authentication for privilege escalation is not disabled globally
# 5.3.6	Ensure sudo authentication timeout is configured correctly 
# 5.3.7	Ensure access to the su command is restricted
# Ensure sudo is installed
sudo_package=$(dpkg -s sudo | grep -i "status: install ok installed")
if [[ -z "$sudo_package" ]]; then
    echo "sudo package is not installed"
    exit 1
fi
# Ensure sudo commands use pty
if ! grep -q "^\s*Defaults\s+use_pty" /etc/sudoers /etc/sudoers.d/*; then
    echo "Defaults use_pty" | sudo tee -a /etc/sudoers
fi
# Ensure sudo log file exists
if ! grep -q "^\s*Defaults\s+logfile=" /etc/sudoers /etc/sudoers.d/*; then
    echo "Defaults logfile=/var/log/sudo.log" | sudo tee -a /etc/sudoers
fi
# Ensure users must provide password for privilege escalation
if ! grep -q "^\s*Defaults\s+env_reset" /etc/sudoers /etc/sudoers.d/*; then
    echo "Defaults env_reset" | sudo tee -a /etc/sudoers
fi
if ! grep -q "^\s*Defaults\s+pwfeedback" /etc/sudoers /etc/sudoers.d/*; then
    echo "Defaults pwfeedback" | sudo tee -a /etc/sudoers
fi
if ! grep -q "^\s*auth\s+required\s+pam_unix.so" /etc/pam.d/sudo; then
    echo "auth required pam_unix.so" | sudo tee -a /etc/pam.d/sudo
fi
# Ensure re-authentication for privilege escalation is not disabled globally
if ! grep -q "^\s*Defaults\s+timestamp_timeout" /etc/sudoers /etc/sudoers.d/*; then
    echo "Defaults timestamp_timeout=15" | sudo tee -a /etc/sudoers
fi
# Ensure sudo authentication timeout is configured correctly
if ! grep -q "^\s*Defaults\s+authenticate" /etc/sudoers /etc/sudoers.d/*; then
    echo "Defaults authenticate" | sudo tee -a /etc/sudoers
fi
if ! grep -q "^\s*Defaults\s+authenticate_timeout" /etc/sudoers /etc/sudoers.d/*; then
    echo "Defaults authenticate_timeout=60" | sudo tee -a /etc/sudoers
fi
# Ensure access to the su command is restricted
if ! grep -q "^auth\s+required\s+pam_wheel.so" /etc/pam.d/su; then
    echo "auth required pam_wheel.so use_uid" | sudo tee -a /etc/pam.d/su
fi
if ! grep -q "^\s*wheel\s\+ALL=(ALL)\s\+ALL" /etc/sudoers /etc/sudoers.d/*; then
    echo "%wheel ALL=(ALL) ALL" | sudo tee -a /etc/sudoers
fi
# CIS security standards 5.4.1 to 5.4.5			
# 5.4.1	Ensure password creation requirements are configured
# 5.4.2	Ensure lockout for failed password attempts is configured
# 5.4.3	Ensure password reuse is limited		
# 5.4.4	Ensure password hashing algorithm is up to date with the latest standards
# Ensure password creation requirements are configured
echo "password requisite pam_cracklib.so ucredit=-1 lcredit=-2 dcredit=-1 ocredit=-1 minlen=14" >> /etc/pam.d/common-password
echo "password required pam_pwhistory.so remember=5" >> /etc/pam.d/common-password
echo "password required pam_unix.so use_authtok sha512 shadow rounds=100000 minlen=14" >> /etc/pam.d/common-password
# Ensure lockout for failed password attempts is configured
sed -i '/^auth.*sufficient.*pam_unix.so/ s/$/ remember=5 unlock_time=900/' /etc/pam.d/common-auth
# Ensure password reuse is limited
echo "password required pam_pwhistory.so remember=5 enforce_for_root" >> /etc/pam.d/common-password
# Ensure password hashing algorithm is up to date with the latest standards
sed -i 's/^password.*pam_unix.so.*$/password\trequired\tpam_unix.so\tuse_authtok\ts3cure/' /etc/pam.d/common-password
# CIS security standards 5.5.1.1 to 5.5.1.5			
# 5.5.1.1 Ensure minimum days between password changes is configured
# 5.5.1.2 Ensure password expiration is 365 days or less
# 5.5.1.3 Ensure password expiration warning days is 7 or more
# 5.5.1.4 Ensure inactive password lock is 30 days or less
# 5.5.1.5 Ensure all users last password change date is in the past
# Ensure minimum days between password changes is configured
sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/g' /etc/login.defs
# Ensure password expiration is 365 days or less
sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t365/g' /etc/login.defs
# Ensure password expiration warning days is 7 or more
sed -i 's/PASS_WARN_AGE\t7/PASS_WARN_AGE\t7/g' /etc/login.defs
# Ensure inactive password lock is 30 days or less
useradd -D -f 30
# Ensure all users last password change date is in the past
chage --mindays 7 --maxdays 365 --warndays 7 --inactive 30 --allusers
passwd -e --all
# CIS security standards 5.5.2 to 5.5.5				
# 5.5.2	Ensure system accounts are secured
# 5.5.3	Ensure default group for the root account is GID 0
# 5.5.4	Ensure default user umask is 027 or more restrictive
# 5.5.5	Ensure default user shell timeout is 900 seconds or less
# Lock system accounts to prevent login
#sudo usermod -L -e 1 <system-account-name>
# Set root default group to GID 0
sudo usermod -g 0 root
# Set default user umask to 027
echo "umask 027" >> /etc/bash.bashrc
echo "umask 027" >> /etc/profile
# Set default user shell timeout to 900 seconds or less
echo "TMOUT=900" >> /etc/profile
# CIS Capitulo 6
# CIS security standards 6.1.1 to 6.1.13					
# 6.1.1	Ensure permissions on /etc/passwd are configured
# 6.1.2	Ensure permissions on /etc/passwd- are configured
# 6.1.3	Ensure permissions on /etc/group are configured
# 6.1.4	Ensure permissions on /etc/group- are configured
# 6.1.5	Ensure permissions on /etc/shadow are configured
# 6.1.6	Ensure permissions on /etc/shadow- are configured
# 6.1.7	Ensure permissions on /etc/gshadow are configured
# 6.1.8	Ensure permissions on /etc/gshadow- are configured
# 6.1.9	Ensure no world writable files exist	
# 6.1.10 Ensure no unowned files or directories exist
# 6.1.11 Ensure no ungrouped files or directories exist	
# Ensure permissions on /etc/passwd are configured
chmod 644 /etc/passwd
chown root:root /etc/passwd
# Ensure permissions on /etc/passwd- are configured
chmod 600 /etc/passwd-
chown root:root /etc/passwd-
# Ensure permissions on /etc/group are configured
chmod 644 /etc/group
chown root:root /etc/group
# Ensure permissions on /etc/group- are configured
chmod 600 /etc/group-
chown root:root /etc/group-
# Ensure permissions on /etc/shadow are configured
chmod 000 /etc/shadow
chown root:shadow /etc/shadow
# Ensure permissions on /etc/shadow- are configured
chmod 000 /etc/shadow-
chown root:shadow /etc/shadow-
# Ensure permissions on /etc/gshadow are configured
chmod 000 /etc/gshadow
chown root:shadow /etc/gshadow
# Ensure permissions on /etc/gshadow- are configured
chmod 000 /etc/gshadow-
chown root:shadow /etc/gshadow-
# Ensure no world writable files exist
find / -xdev -type f -perm -0002 -exec chmod o-w {} +
# Ensure no unowned files or directories exist
find / -xdev \( -nouser -o -nogroup \) -exec chown root:root {} +
# Ensure no ungrouped files or directories exist
find / -xdev -nogroup -exec chown root:root {} +
# CIS security standards 6.2.1 to 6.2.17			
# 6.2.1	Ensure accounts in /etc/passwd use shadowed passwords		
# 6.2.2	Ensure /etc/shadow password fields are not empty		
# 6.2.3	Ensure all groups in /etc/passwd exist in /etc/group		
# 6.2.4	Ensure shadow group is empty		
# 6.2.5	Ensure no duplicate UIDs exist		
# 6.2.6	Ensure no duplicate GIDs exist		
# 6.2.7	Ensure no duplicate user names exist		
# 6.2.8	Ensure no duplicate group names exist		
# 6.2.9	Ensure root PATH Integrity	
# 6.2.10 Ensure root is the only UID 0 account
# 6.2.11 Ensure local interactive user home directories exist
# 6.2.12 Ensure local interactive users own their home directories
# 6.2.13 Ensure local interactive user home directories are mode 750 or more restrictive	
# 6.2.14 Ensure no local interactive user has .netrc files
# 6.2.15 Ensure no local interactive user has .forward files
# 6.2.16 Ensure no local interactive user has .rhosts files
# 6.2.17 Ensure local interactive user dot files are not group or world writable
# Ensure accounts in /etc/passwd use shadowed passwords
grep -E -q '^\+:|^+:' /etc/passwd
if [[ $? -eq 0 ]]; then
    echo "Failed: Accounts in /etc/passwd use shadowed passwords"
else
    echo "Passed: Accounts in /etc/passwd use shadowed passwords"
fi
# Ensure /etc/shadow password fields are not empty
awk -F: '($2 == "" ) { print $1 " does not have a password "} ' /etc/shadow
if [[ $? -eq 0 ]]; then
    echo "Failed: /etc/shadow password fields are empty"
else
    echo "Passed: /etc/shadow password fields are not empty"
fi
# Ensure all groups in /etc/passwd exist in /etc/group
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
    grep -q -P "^.*?:[^:]*:$i:" /etc/group
    if [[ $? -eq 1 ]]; then
        echo "Failed: Group $i is referenced by /etc/passwd but does not exist in /etc/group"
    fi
done
if [[ $? -eq 0 ]]; then
    echo "Passed: All groups in /etc/passwd exist in /etc/group"
fi
# Ensure shadow group is empty
if [[ $(grep -E -v '^\+' /etc/group | awk -F: '($4 == "root") { print }') == "" ]]; then
    echo "Passed: Shadow group is empty"
else
    echo "Failed: Shadow group is not empty"
fi
# Ensure no duplicate UIDs exist
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [[ $1 -gt 1 ]]; then
        users=$(grep -E "^.*?:[^:]*:$2:" /etc/passwd | cut -f1 -d":")
        echo "Failed: Duplicate UID ($2): ${users}"
    fi
done
if [[ $? -eq 0 ]]; then
    echo "Passed: No duplicate UIDs exist"
fi
# Ensure no duplicate GIDs exist
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [[ $1 -gt 1 ]]; then
        groups=$(grep -E "^.*?:[^:]*:$2:" /etc/group | cut -f1 -d":")
        echo "Failed: Duplicate GID ($2): ${groups}"
    fi
done
if [[ $? -eq 0 ]]; then
    echo "Passed: No duplicate GIDs exist"
fi
# Ensure no duplicate user names exist
echo "Checking for duplicate user names..."
if [ $(cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | awk '{print $1}') -eq 1 ]; then
  echo "No duplicate user names found."
else
  echo "Duplicate user names found!"
  cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -cd
fi
# Ensure no duplicate group names exist
echo "Checking for duplicate group names..."
if [ $(cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | awk '{print $1}') -eq 1 ]; then
  echo "No duplicate group names found."
else
  echo "Duplicate group names found!"
  cat /etc/group | cut -f1 -d":" | sort -n | uniq -cd
fi
# Ensure root PATH Integrity
echo "Checking root PATH integrity..."
if [ "$(echo $PATH | grep ::)" != "" ]; then
  echo "Empty directory in PATH (::)"
fi
if [ "$(echo $PATH | grep :$)" != "" ]; then
  echo "Trailing : in PATH"
fi
p=$(echo $PATH | sed -e 's/:/ /g')
set -- $p
while [ "$1" != "" ]; do
  if [ "$1" = "." ]; then
    echo "PATH contains ."
    shift
    continue
  fi
  if [ -d $1 ]; then
    dirperm=$(ls -ldH $1 | cut -f1 -d" ")
    if [ $(echo $dirperm | cut -c6) != "-" ]; then
      echo "Group Write permission set on directory $1"
    fi
    if [ $(echo $dirperm | cut -c9) != "-" ]; then
      echo "Other Write permission set on directory $1"
    fi
    dirown=$(ls -ldH $1 | awk '{print $3}')
    if [ "$dirown" != "root" ] ; then
      echo $1 is not owned by root
    fi
  else
    echo $1 is not a directory
  fi
  shift
done
# Ensure root is the only UID 0 account
echo "Checking for accounts with UID 0..."
if [ $(grep -c ^root: /etc/passwd) -eq 1 ]; then
  echo "Only one account with UID 0: root"
else
  echo "More than one account with UID 0!"
  grep ^root: /etc/passwd
fi
# Ensure local interactive user home directories exist
echo "Checking local interactive user home directories..."
while IFS=: read -r user _ uid gid _ home shell; do
    if [ "$uid" -ge 1000 -a ! -d "$home" -a "$shell" != "/usr/sbin/nologin" ]; then
        echo "The home directory ($home) of user $user does not exist."
    fi
done < /etc/passwd
# Ensure local interactive users own their home directories
echo "Checking local interactive users own their home directories..."
while IFS=: read -r user _ uid gid _ home shell; do
    if [ "$uid" -ge 1000 -a -d "$home" -a "$shell" != "/usr/sbin/nologin" ]; then
        owner=$(stat -c "%U" "$home")
        if [ "$user" != "$owner" ]; then
            echo "The home directory ($home) of user $user is owned by $owner."
        fi
    fi
done < /etc/passwd
# Ensure local interactive user home directories are mode 750 or more restrictive
echo "Checking local interactive user home directories permissions..."
while IFS=: read -r user _ uid gid _ home shell; do
    if [ "$uid" -ge 1000 -a -d "$home" -a "$shell" != "/usr/sbin/nologin" ]; then
        perms=$(stat -c "%a" "$home")
        if [ "$perms" -gt 750 ]; then
            echo "The home directory ($home) of user $user has permissions $perms."
        fi
    fi
done < /etc/passwd
# Ensure no local interactive user has .netrc files
echo "Checking local interactive user .netrc files..."
while IFS=: read -r user _ uid gid _ home shell; do
    if [ "$uid" -ge 1000 -a -d "$home" -a "$shell" != "/usr/sbin/nologin" ]; then
        if [ -e "$home/.netrc" ]; then
            echo "User $user has a .netrc file in their home directory ($home)."
        fi
    fi
done < /etc/passwd
# Ensure no local interactive user has .forward files
echo "Checking local interactive user .forward files..."
while IFS=: read -r user _ uid gid _ home shell; do
    if [ "$uid" -ge 1000 -a -d "$home" -a "$shell" != "/usr/sbin/nologin" ]; then
        if [ -e "$home/.forward" ]; then
            echo "User $user has a .forward file in their home directory ($home)."
        fi
    fi
done < /etc/passwd
# Ensure no local interactive user has .rhosts files
echo "Checking for .rhosts files..."
if [ $(find /home -maxdepth 2 -name .rhosts | wc -l) -eq 0 ]; then
  echo "No .rhosts files found."
else
  echo "Some .rhosts files found!"
  find /home -maxdepth 2 -name .rhosts -exec ls -ld {} \;
fi
# Ensure local interactive user dot files are not group or world writable
for dir in $(grep -vE "^(root|halt|sync|shutdown)" /etc/passwd | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'); do
  for file in $dir/.[A-Za-z0-9]*; do
    if [ ! -h "$file" ] && [ -f "$file" ]; then
      fileperm=$(ls -ld $file | cut -f1 -d" ")
      if [ $(echo $fileperm | cut -c6) != "-" ]; then
        echo "Group Write permission set on file $file"
      fi
      if [ $(echo $fileperm | cut -c9) != "-" ]; then
        echo "Other Write permission set on file $file"
      fi
    fi
  done
done 
