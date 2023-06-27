'''
Serverside monitor...

1. Scan for new nodes
2. New Processes, 
3. New Apps, 
4. New Vulnerabilities
5. Analysis
6. Update vulnerability information

'''
# ToDo: link db using config file.

# Database connection and existing process retrieval...
import couchdb2, json, os, schedule, time, os, schedule, nmap, re, winsound
from threading import Thread
from datetime import datetime
import numpy as np

db_host_list, db_node_apps, db_node_ports, db_vulns = [], [], [], [] # for tracking

os.environ["PATH"] += os.pathsep + 'C:/Graphviz2.38/bin'
db_user, db_pass, db_host, db_port, db_name = 'admin', 'Samsung_1234', '192.168.0.113', '5984', 'cyvid_nodes'
server = couchdb2.Server("http://%s:%s@%s:%s" % (db_user, db_pass, db_host, db_port))
master_doc = {} # document that will contain nodes data

if server.up(): # if server is up and ready
    if db_name in server: # already existing database # if db.exists():
        db = server[db_name]
    else: # create database if does not exist
        server.create(db_name) # create database
else: # exit if server not running
    print('Server not responding, exiting program!')
    import sys
    sys.exit()

# Check Nodes - Verify IP Address
def check_ip(ip_addr):
    regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''
    if(re.search(regex, ip_addr)):  
        return True

    else:  
        return False

# Check Nodes - Scan Network
# ToDo: if required scan all networks and generate dependency graphs.
def scan_network_nodes(network_id):
    host_list, new_hosts = [], []
    # g = Graph('G', filename=file_path+'/'+graph_file, engine='sfdp')
    if check_ip(network_id):
        # print('Valid IP with length', len(network_id))
        network = network_id + '/24'
        # print("Scanning network please wait...")
        nmap.scan(hosts=network, arguments='-sn')
        host_list = [(x, nmap[x]['status']['state']) for x in nmap.all_hosts()]
        # print('DB Hosts', db_host_list)
        for host, status in host_list:
            # print("Found host:", host)
            if host not in db_host_list: # Add host to new host list if not found in db.
                # print('Not Found Host', host)
                new_hosts.append(host)
            # if (host!=network_id): # if host is the router, do not add an edge in the graph
                # g.edge(host, network_id)
        winsound.Beep(440, 500) # Beep
        print(' Found',len(host_list), 'alive hosts. Newly discovered node(s)', len(new_hosts))
        if len(new_hosts) != 0: 
            print(' ** New host(s):', new_hosts, '\n')
            write_new_data('** Found New host(s): ' + ', '.join(new_hosts))
            # print('Loading graph...')
            # g.view() # load node graph
    else:
        print('Invalid IP address')
    # return host_list
    
def scan_network():
    # db_host_list = [] # hosts recorded already in DB
    t1 = time.localtime()
    current_time = time.strftime("%H:%M:%S", t1)
    print('\n** Starting network scanner at', current_time, '\n')

    for doc in db: # add existing nodes ip to the list
        # print(doc['HostIP'])
        db_host_list.append(doc['HostIP'])

    hosts = scan_network_nodes(network_id)


def load_db_master():
    t2 = time.localtime()
    current_time = time.strftime("%H:%M:%S", t2)
    print('\n'+current_time, 'Fetching existing data...\n')
    db = server[db_name]
    for doc in db:
        db_app_list, db_users, db_applications, db_ports, db_vulns = [], [], [], [], []

        try: # loading process list only, for all nodes
            # print(doc['HostName'], 'processes in db\t\t', len(doc['RunningProcesses']))
            db_applications = doc['applications']
            db_ports = doc['OpenPorts']
            db_vulns = doc['CVEsFound']
            for key in doc['RunningProcesses']:
                db_app_list.append(key)
                for j in doc['RunningProcesses'][key]:
                    if j['username'] not in db_users:
                        db_users.append(j['username'])
            print('', doc['HostName']+':', '[Recorded processes:', len(doc['RunningProcesses']), ', Users:', 
                  len(db_users), ', Applications:', len(db_applications), ', open ports:', str(len(db_ports)), ', Vulnerabilities:',
                  str(len(db_vulns))+']')

            master_doc[doc['HostName']] = {
                                            'app_list': db_app_list,
                                            'app_users': db_users,
                                            'applications': db_applications,
                                            'ports': db_ports,
                                            'CVEsFound': db_vulns
                                          }
            # print(json.dumps(master_doc, indent=2))
            # print(json.dumps(master_doc[doc['HostName']]['CVEsFound'], indent=2))
            
        except KeyError:
            continue
            # print(doc['HostName'], 'processes in db \t 0')
            # master_doc[doc['HostName']] = [] # add empty list when nothing found
            # db_applications, db_ports, db_vulns = [], [], []
    print()

# Find difference of two lists
def Diff(li1, li2):
    return (list(list(set(li1)-set(li2)) + list(set(li2)-set(li1))))

def check_for_changes():
    t3 = time.localtime()
    current_time = time.strftime("%H:%M:%S", t3)
    print(current_time, '\nLooking for changes in node processes, applications, and ports...\n')
    found_new_processes, found_new_apps, found_new_ports, found_new_vulns = False, False, False, False
    
    for doc2 in db:
        app_list, applications, ports, vulns = [], [], [], []
        try:
            applications = doc2['applications']
            ports = doc2['OpenPorts']
            vulns = doc2['CVEsFound']
            for key in doc2['RunningProcesses']:
                app_list.append(key)
            # find changes, previous & current
            new_processes = Diff(master_doc[doc2['HostName']]['app_list'], app_list) 
            new_applications = Diff(master_doc[doc2['HostName']]['applications'], applications)
            new_ports = Diff(master_doc[doc2['HostName']]['ports'], ports)
            # print('\nLength:', len(vulns), len(master_doc[doc2['HostName']]['CVEsFound']))
            new_vulns = Diff(master_doc[doc2['HostName']]['CVEsFound'], vulns)
            # new_applications = np.setdiff1d(applications, master_doc[doc2['HostName']]['applications'])
            # new_ports = np.setdiff1d(ports, master_doc[doc2['HostName']]['applications'])
            
            # print(doc2['HostName']+':', '[New processes:', len(new_processes), len(app_list), 
            #      'Applications:', len(new_applications), '', len(applications), 'ports:', 
            #      len(new_ports), str(len(ports))+']') # Debug
            
            if len(new_processes) > 0:
                found_new_processes = True
                winsound.Beep(440, 500) # Beep
                print('\n **', len(new_processes), 'New process(es) found **')
                write_new_data(doc2['HostName']+': '+str(len(new_processes))+
                                   ' New process(es). '+', '.join(new_processes))
                print(doc2['HostName']+':', new_processes)

            if len(new_applications) > 0:
                found_new_apps = True
                winsound.Beep(440, 500) # Beep
                print('\n **', len(new_applications), 'New application(s) found **')
                write_new_data(doc2['HostName']+': '+str(len(new_applications))+
                               ' New application(s). '+', '.join(new_applications))
                print(doc2['HostName']+':', new_applications)
                
            if len(new_ports) > 0:
                found_new_apps = True
                winsound.Beep(440, 500) # Beep
                print('\n **', len(new_ports), 'New port(s) found **')
                write_new_data(doc2['HostName']+': '+str(len(new_ports))+' New port(s). '+', '.join(new_ports))
                print(doc2['HostName']+':', new_ports)
             
            if len(new_vulns) > 0:
                found_new_vulns = True
                winsound.Beep(440, 500) # Beep
                print('\n **', len(new_vulns), 'New vulnerabilities found **')
                write_new_data(doc2['HostName']+': '+str(len(new_vulns))+' New vulnerabilities. '+', '.join(new_vulns))
                print(doc2['HostName']+':', new_vulns)

        except KeyError:
            # print('** No data found for', doc2['HostName']) # Debug
            continue

    if not found_new_processes: print('No new process found.')
    if not found_new_apps: print('No new applications found.')
    if not found_new_ports: print('No new open ports found.')
    if not found_new_vulns: print('No new vulnerabilities found.')
    #master_doc = {}
    master_doc.clear() # reset master doc to update it
    load_db_master() # reload new master doc, not to repeat changes each time        


def run_daily_updates_for_datasets(): # okay
    t3 = time.localtime()
    current_time = time.strftime("%H:%M:%S", t3)
    print('\n** Starting daily update for datasets at', current_time) 
    os.system('python update_datasets.py') # Replace python with python3 and file name where needed.
    
    
def write_new_data(data):
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    f = open("log.txt", "a")
    f.write(dt_string+' '+data+'\n\n')
    f.close()

# Start execution
nmap = nmap.PortScanner() 
network_id = input('Please provide network id to scan new nodes from: ')

t = time.localtime()
current_time = time.strftime("%H:%M:%S", t)
print('\nServer scheduler started at', current_time)

# load_db_master() 
# print(json.dumps(master_doc, indent=2))

check_for_changes()
# Every n minutes 
schedule.every(1).minutes.do(scan_network) # Scan for new nodes
schedule.every(5).minutes.do(check_for_changes) # Scan for new applications, processes, ports
schedule.every().day.at("06:00").do(run_daily_updates_for_datasets) # Run daily update at 6am


while True: 
    # Checks whether a scheduled task is pending to run or not 
    schedule.run_pending()
    time.sleep(1)