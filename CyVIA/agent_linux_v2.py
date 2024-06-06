import subprocess, sys, json, time, os
scripts_path, node_config, apps_list, port_list = "scripts/linux_client_info.sh", "linux_node_config.txt", "linux_apps_list.txt", "linux_open_ports.txt"

# Run the script to collect node information
def run_script():
    from subprocess import call
    subprocess.call(scripts_path, shell=True)
    time.sleep(3) # Wait a few seconds, file content being written


def load_node_info():
    file = open(node_config, 'r')
    node_info = {}
    #Repeat for each song in the text file
    for line in file:
        cur_line = line.rstrip().split(",") # read lines and remove blank lines
        node_info[cur_line[0]] = cur_line[1]
    file.close()
    return node_info


def load_node_apps():
    node_apps = [line.rstrip('\n') for line in open(apps_list)]
    return node_apps


def load_open_ports():
    node_ports = [line.rstrip('\n') for line in open(port_list)]
    return node_ports    
    

def insert_to_db(node_info, node_apps, node_ports):
    import couchdb2, json, config
    db_name, erase_db = 'cyvia_nodes', False
    server = couchdb2.Server("http://%s:%s@%s:%s" % (config.db_user, config.db_pass, config.db_host, config.db_port))

    if server.up(): # if server is up and ready
        # print('Server status: ('+str(server.version)+') up and running!')               
        if db_name in server: # already existing database # if db.exists():
            if erase_db:
                db = server[db_name]
                db.destroy() # deletes all records
                server.create(db_name)
                db = server[db_name]
            else:
                # print('Database '+db_name+' found, selecting...')
                db = server[db_name]
                # print('Database selected:', str(db))
        else: # create database if does not exist
            print('Database '+db_name+' does not exist, creating...')
            server.create(db_name)
            db = server[db_name]
            # print('Database selected:', str(db))
            
        # Inserting node data...
        # print('Inserting node data...')
        doc = {
                "HostName": node_info['HostName'],
                "HostIP": node_info['HostIP'],
                "HostGateway": node_info['HostGateway'],
                "HostOS": node_info['HostOS'],
                "applications": node_apps,
                "OpenPorts": node_ports,
                "RunningProcesses": current_processes
        } # print('Doc:\n', json.dumps(doc, indent=4))
        db.put(doc)
        print('Done.')
    else: # exit if server not running
        print('Server not responding, exiting program!')
        sys.exit()


from os import path
if path.exists("linux_apps_list.txt"): os.system('rm linux_apps_list.txt')
if path.exists("linux_node_config.txt"): os.system('rm linux_node_config.txt')
if path.exists("linux_open_ports.txt"): os.system('rm linux_open_ports.txt')
if path.exists("linux_processes.csv"): os.system('rm linux_processes.csv')

print('Done.\nCapturing system information...', end=' ')

run_script()    
node_info = load_node_info()
node_apps = load_node_apps() 
node_ports = load_open_ports()

# Capturing processes and grouping them.
import psutil, json
import pandas as pd
procs = {p.pid: p.info for p in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cpu_percent', 'memory_percent', 'cpu_times', 'num_threads'])}
current_processes = {}
for name, group in pd.DataFrame.from_records(list(procs.values())).groupby('name'):
    current_processes[name] = list(group[['pid', 'exe', 'username', 'num_threads', 'cpu_percent', 'memory_percent', 'cpu_times']].to_dict(orient='index').values())
    
print('Done.\nTotal', len(current_processes), 'running.')
    
# print(current_processes)
insert_to_db(node_info, node_apps, node_ports)