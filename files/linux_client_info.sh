# Common linux app list:
dpkg-query -W -f='${binary:Package} ${Version}\n' > linux_apps_list.txt

# Centos App_list:
# rpm -qa > linux_apps_list.txt

echo -n "HostName,`hostname`" > linux_node_config.txt
echo  >> linux_node_config.txt
echo -n "HostIP,`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -n 1`" >> linux_node_config.txt
echo  >> linux_node_config.txt
echo -n "HostGateway,`netstat -rn |awk '{if($1=="0.0.0.0") print $2}'`" >> linux_node_config.txt
echo  >> linux_node_config.txt
echo -n "HostOS,`uname -srm`" >> linux_node_config.txt

nmap 127.0.0.1 -p 1-65535 | awk 'NR >= 7 {print $3":"$1}' | sed 's/\/tcp//g' | sed '$d' | sed '$d' > linux_open_ports.txt

ps aux | awk '{print $1","$2","$3","$4","$5","$6","$7","$8","$9","$10","$11}' > linux_processes.csv