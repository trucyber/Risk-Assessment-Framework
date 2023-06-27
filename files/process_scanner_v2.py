''' Process Monitor PART 2 v2.0 Windows, Linux, Mac '''
# Capture currently running processes and match with recorded process, highlight and add newly found processes.
# ToDo: link db using config file.

import socket, os, psutil, json, couchdb2
import pandas as pd 

# Get hostname and hostIP
hostname = socket.gethostname() # getting the hostname by socket.gethostname() method
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80)) # make an outgoing connection to check the interface in use.
ip_address = s.getsockname()[0] 
print('\n HostName:', hostname, 'HostIP:', ip_address) # printing the hostname and ip_address
s.close()

# Capture current processes...
print(' Processes curently running:', end=' ')
current_processes, node_document, db_processes, new_processes = {}, {}, {}, {}

procs = {p.pid: p.info for p in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cpu_percent', 'memory_percent', 'cpu_times', 'num_threads'])}
for name, group in pd.DataFrame.from_records(list(procs.values())).groupby('name'):
    current_processes[name] = list(group[['pid', 'exe', 'username', 'num_threads', 'cpu_percent', 'memory_percent', 'cpu_times']].to_dict(orient='index').values())

print(len(current_processes), end='')
print(' Previously recorded:', end=' ')

# Database connection and existing process retrieval...
db_user, db_pass, db_host, db_port, db_name = 'admin', 'Samsung_1234', '192.168.0.113', '5984', 'cyvid_nodes'
server = couchdb2.Server("http://%s:%s@%s:%s" % (db_user, db_pass, db_host, db_port))

if server.up(): # if server is up and ready
    if db_name in server: # already existing database # if db.exists():
        db = server[db_name]
    else: # create database if does not exist
        server.create(db_name) # create database
else: # exit if server not running
    print('Server not responding, exiting program!')
    import sys
    sys.exit()

for doc in db:
    # if doc['HostIP']==ip_address: # db ip for test host is on different network so using hostname instead, use this later
    if doc['HostName']==hostname: # disable this and use above line later.
        #print('Done.\n Host ('+hostname+') profile found with IP '+ip_address)
        node_document = doc # keeping found document data in found_doc
        try:
            db_processes = doc['RunningProcesses']
            new_processes = db_processes
        except KeyError:
            db_processes, new_processes = {}, {}

# Check lengths of database and new lists 
print(len(db_processes))

# Process discovery mode
process_discovery_mode, search_key_found = True, False
found_processes, found_apps = 0, 0

# Match newly discovered processes with previously recorded processes...
print(' Finding new processes if any...\n')
for i in current_processes:
    if i in db_processes: # find app name if present in db
        # print('key', i, 'present with', len(current_processes[i]), 'values currently, and', len(db_processes[i]), 'in db')
        for item_a in current_processes[i]: # looping through keys in the current process item
            search_key_found = False # force false for new key
            for item_b in db_processes[i]: # looping through keys in the db process item
                if (item_a['exe'] == item_b['exe']) and (item_a['username'] == item_b['username']): # if item_a['pid'] == item_b['pid'] 
                    # print('file and user matched')
                    search_key_found = True
                    break
            if not search_key_found: # if key (PID) is not found
                print(' ** New PID', item_a['pid'], 'found under the application', i, 'not recorded previously')
                found_processes += 1
                new_processes[i].append(item_a) # add PID

    else: # Key not found, a new process is found, log it.
        print(' ## New application', i, 'found (not recorded previously) with', len(current_processes), 'processes:')
        doc = {i: current_processes[i]}
        print(json.dumps(doc, indent=2))
        found_apps += 1
        found_processes += len(current_processes[i])
        new_processes.update(doc) # remove [] from list, convert to dict, and add item

print('Found '+str(found_apps)+' new application(s) and '+str(found_processes)+' new process(es) among the '+str(len(current_processes))+' currently running.')

if found_apps != 0 or found_processes != 0:
    if process_discovery_mode:
        print(' Recording newly discovered process...', end=' ')
        # Update the node document
        node_document = {
                            '_id': node_document['_id'],
                            '_rev': node_document['_rev'],
                            'HostName': node_document['HostName'],
                            'HostIP': node_document['HostIP'],
                            'HostGateway': node_document['HostGateway'],
                            'HostOS': node_document['HostOS'],
                            'applications': node_document['applications'],
                            'DeviceType': node_document['DeviceType'],
                            'ControlPolicy': node_document['ControlPolicy'],
                            'AdversarialPolicy': node_document['AdversarialPolicy'],
                            'OpenPorts': node_document['OpenPorts'],
                            'CVEsFound': node_document['CVEsFound'],
                            'ServicesProvided': node_document['ServicesProvided'],
                            'ServicesReceived': node_document['ServicesReceived'],
                            'RunningProcesses': new_processes    
                        }
        db.put(node_document)
        print('Done.')