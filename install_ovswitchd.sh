#!/bin/bash

# Adding OVS as a service
echo -e "\n-Adding OpenVSwitch service"
echo -e '#!/bin/bash
#
# start/stop openvswitch
### BEGIN INIT INFO
# Provides: openvswitchd
# Required-start: $remote_fs $syslog
# Required-stop: $remote_fs $syslog
# Default-start: 2 3 4 5
# Default-stop: 0 1 6
# Short-description: OpenVSwitch daemon
# chkconfig: 2345 9 99
# description: Activates/Deactivates all Open vSwitch to start at boot time.
# processname: openvswitchd
# config: /usr/local/etc/openvswitch/conf.db
# pidfile: /usr/local/var/run/openvswitch/ovs-vswitchd.pid
### END INIT INFO\n

PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin
export PATH\n

# Source function library. . /etc/rc.d/init.d/functions
. /lib/lsb/init-functions\n

stop()
{
echo "
Stopping openvswitch..."\n

if [ -e /usr/local/var/run/openvswitch/ovs-vswitchd.pid ]; then
pid=$(cat /usr/local/var/run/openvswitch/ovs-vswitchd.pid)
/usr/local/bin/ovs-appctl -t /usr/local/var/run/openvswitch/ovs-vswitchd.$pid.ctl exit
rm -f /usr/local/var/run/openvswitch/ovs-vswitchd.$pid.ctl
fi\n

if [ -e /usr/local/var/run/openvswitch/ovsdb-server.pid ]; then
pid=$(cat /usr/local/var/run/openvswitch/ovsdb-server.pid)
/usr/local/bin/ovs-appctl -t /usr/local/var/run/openvswitch/ovsdb-server.$pid.ctl exit
rm -f /usr/local/var/run/openvswitch/ovsdb-server.$pid.ctl
fi\n

rm -f /var/lock/subsys/openvswitchd
echo "OK"
}\n

start()
{
echo "
Starting openvswitch..."
/usr/local/sbin/ovsdb-server /usr/local/etc/openvswitch/conf.db \
--remote=punix:/usr/local/var/run/openvswitch/db.sock \
--remote=db:Open_vSwitch,Open_vSwitch,manager_options \
--private-key=db:Open_vSwitch,SSL,private_key \
--certificate=db:Open_vSwitch,SSL,certificate \
--bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
--pidfile --detach\n

/usr/local/bin/ovs-vsctl --no-wait init
/usr/local/sbin/ovs-vswitchd unix:/usr/local/var/run/openvswitch/db.sock --pidfile --detach\n

mkdir -p /var/lock/subsys
touch /var/lock/subsys/openvswitchd
echo "
OpenVSwitch started succesfully!"
}\n

# See how we were called.
case $1 in
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
status ovs-vswitchd
;;
*)
echo "Usage: openvswitchd {start|stop|status|restart}."
exit 1
;;
esac\n
exit 0' > /etc/init.d/openvswitchd &&
chmod +x /etc/init.d/openvswitchd &&
update-rc.d openvswitchd defaults &&
