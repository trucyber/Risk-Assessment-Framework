import subprocess, sys, json, time, os, psutil, couchdb2, config
import pandas as pd
import numpy as np
from multiprocessing.pool import ThreadPool

scripts_path, node_config, apps_list, port_list = "scripts/win_client_info.ps1", "win_node_config.txt", "win_apps_list.txt", "win_open_ports.txt"

# For application and port tracking
db_node_apps, new_node_apps, db_node_ports, new_node_ports, db_total_cves = [], [], [], [], [] # current is node_apps, node_ports
node_document, db_product_to_cve = {}, {} # keeping track of db document if found

# Run the script to collect node information
def run_script():
    p = subprocess.Popen(["powershell.exe", scripts_path], stdout=sys.stdout)
    p.communicate()
    time.sleep(3) # Wait a few seconds, file content being written


def load_node_info():
    file = open(node_config, 'r', encoding='utf-16')
    node_info = {}
    #Repeat for each song in the text file
    for line in file:
        cur_line = line.rstrip().split(",") # read lines and remove blank lines
        node_info[cur_line[0]] = cur_line[1]
    file.close()

    # print('HostName:', node_info['HostName'])
    # print('HostIP:', node_info['HostIP'])
    # print('HostGateway:', node_info['HostGateway'])
    # print('HostOS:', node_info['HostOS'])
    # print('Node information saved in the dictionary node_info')
    # print()
    return node_info

    
def load_node_apps():
    file = open(apps_list, 'r', encoding='utf-16')
    lines = file.readlines()[4:] # Skip first 4 lines 
    node_apps = []
    
    #Repeat for each item in the text file
    for line in lines:
        cur_line = line.rstrip()# read lines and remove blank lines
        if len(cur_line)!=0: # if line is not blank 
            splits = cur_line.replace('-','').split()
            res = []
            [res.append(x) for x in splits if x not in res]
            
            # print(" ".join(res))
            node_apps.append(" ".join(res))
    file.close()
    return node_apps


def load_open_ports():
    node_ports = [line.replace('/tcp','').rstrip().rstrip('\n') for line in open(port_list)]
    return node_ports 
    

# method to find CVEs for products:
total_cves, products_not_found, cves_not_found = [], [], [] # list of total cves for all apps
product_to_cve, cve_to_product = {}, {} # dictionary to keep product to CVE, CVE to product mapping
def find_cves(product):
    product = product.replace(" ", "+")
    url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="+product
    # print('Finding for:', product, '-', end=' ')
    df_list = pd.read_html(url)
    if (len(df_list)!=5):
        print("Page style changed at MITRE website, reconfigure")
    else: 
        #print('\n### Found Data for product:\n', ((df_list[2]['Name']).to_string(index=False).split()), '\n')
        found_cves = ((df_list[2]['Name']).to_string(index=False).split())
        if found_cves == ['Series([],', ')']: # if no data is found for product
            products_not_found.append(product)
        else: # if CVE list found
            product_to_cve[product] = found_cves # product to CVE mapping
            total_cves.extend(found_cves) # add found CVEs in the total_cves list

# def find_app_vulnerabilities(application_list):
#    print('Finding vulnerabilities...', end=' ')

def Diff(li1, li2):
    return (list(list(set(li1)-set(li2)) + list(set(li2)-set(li1))))

def insert_to_db(node_info, node_apps, node_ports, product_to_cve, total_cves):
    db_node_apps, db_node_ports, db_total_cves = [], [], []
    db_product_to_cve = {}
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
            # print('Database '+db_name+' does not exist, creating...')
            server.create(db_name)
            db = server[db_name]
            #print('Database selected:', str(db))

        # Inserting node data... Check if doc already exists first.
        doc_found = False # if document is found, set true later
        for doc in db:
            if doc['HostName']==node_info['HostName']:
                doc_found = True
                node_document = doc
                try:
                    db_node_apps = doc['applications']
                    db_node_ports = doc['OpenPorts']
                    db_total_cves = doc['CVEsFound']
                    # db_product_to_cve = doc['CVEs']
                except KeyError:
                    # db_node_apps, db_node_ports, db_total_cves = [], [], []
                    # db_product_to_cve = {}
                    pass

        # Match current apps and ports with recorded apps and ports.
        new_node_apps = np.setdiff1d(node_apps, db_node_apps)  # items in first list not in second
        new_node_ports = np.setdiff1d(node_ports, db_node_ports)
        
        # CVEs repeat, in the list there will be repeatative entries, comparison can not be done like this!!!
        # if len(db_total_cves)==0: new_node_cves = total_cves
        # else: new_node_cves = np.setdiff1d(total_cves, db_total_cves)
        new_node_cves = Diff(db_total_cves, total_cves)
            
        # print('\nResults:', len(db_total_cves), len(total_cves), len(db_node_apps), len(node_apps), len(db_node_ports), len(node_ports))
        print(' ## Found', len(new_node_apps) , 'newly installed application(s).')
        print(' ## Found', len(new_node_ports) , 'newly open port(s).')
        print(' ## Found', len(new_node_cves) , 'unique vulnerabilities, out of', len(total_cves), 'total.')
   ##   Enable next 2 lines after fixting     
        # print(' Total '+str(len(total_cves))+' CVEs in '+str(len(node_apps))+' products and for '+
        #      str(len(products_not_found))+' products, no CVE information found.')
        if len(products_not_found) > 0: print(' Products:', products_not_found)        
        print(' Generating node profile...', end=' ')
        # merge new apps and ports with existing
        node_apps.extend(new_node_apps)
        node_ports.extend(new_node_ports)
        
        if doc_found == True:
            node_document = {
                                '_id': node_document['_id'],
                                '_rev': node_document['_rev'],
                                'HostName': node_document['HostName'],
                                'HostIP': node_document['HostIP'],
                                'HostGateway': node_document['HostGateway'],
                                'HostOS': node_document['HostOS'],
                                'applications': node_apps,
                                'DeviceType': node_document['DeviceType'],
                                'ControlPolicy': node_document['ControlPolicy'],
                                'AdversarialPolicy': node_document['AdversarialPolicy'],
                                'OpenPorts': node_ports,
                                'CVEsFound': total_cves,
                                'ServicesProvided': node_document['ServicesProvided'],
                                'ServicesReceived': node_document['ServicesReceived'],
                                'RunningProcesses': current_processes
                            }# 'CVEs': product_to_cve,
        else:
            #print('Inserting node data...')
            node_document = {
                                "HostName": node_info['HostName'],
                                "HostIP": node_info['HostIP'],
                                "HostGateway": node_info['HostGateway'],
                                "HostOS": node_info['HostOS'],
                                "applications": node_apps, 
                                "OpenPorts": node_ports,
                                "CVEsFound": total_cves,
                                "RunningProcesses": current_processes
                            } # print('Doc:\n', json.dumps(doc, indent=4))
        db.put(node_document)
        print('Done.')
    else: # exit if server not running
        print('Server not responding, exiting program!')
        sys.exit()

print('\n Removing old files...', end=' ')
os.system('del win_apps_list.txt, win_node_config.txt, win_open_ports.txt, win_processes.csv') # remove if file exists.
print('Done.\n Capturing running processes...', end=' ')

# Capturing processes and grouping them.
procs = {p.pid: p.info for p in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cpu_percent', 'memory_percent', 'cpu_times', 'num_threads'])}
current_processes = {}
for name, group in pd.DataFrame.from_records(list(procs.values())).groupby('name'):
    current_processes[name] = list(group[['pid', 'exe', 'username', 'num_threads', 'cpu_percent', 'memory_percent', 'cpu_times']].to_dict(orient='index').values())
    
print('Done. Total', len(current_processes), 'running processes.')
#print(json.dumps(current_processes, indent=2))

# Capturing host information and installed applications.
print(' Capturing host information...', end=' ')
run_script()    
node_info = load_node_info()
node_apps = load_node_apps()
print('Done.\n Capturing open ports...', end=' ')

# find the open ports
os.system('for /f "tokens=3,1 skip=4" %i in (\'nmap 127.0.0.1 -p 1-65535 ^| findstr /v "PORT"\') do @echo %j:%i >> win_open_ports.txt')
node_ports = load_open_ports()
node_ports.pop()
print('Done.')


# Finding vulnerarbilities in node applications
print(' Finding vulnerabilities', end=' ')
# Threaded product vulnerarbility finder
results = ThreadPool(8).imap_unordered(find_cves, node_apps)
try:
    for i in results:
        print('.', end='') # print(i)
except UnicodeEncodeError:
    pass
print('Done.\n')

#print('Done\n ## Found '+str(len(total_cves))+' CVEs in '+str(len(node_apps))+' products and for '+
#      str(len(products_not_found))+' products, no CVE information found')
#if len(products_not_found) > 0: print(' Products:', products_not_found)

# CVE to Product mapping
for k, v in product_to_cve.items():
    if isinstance(v, list):
        for c in v:
            if c in cve_to_product.keys():
                cve_to_product[c].extend([k])
            else:
                cve_to_product[c] = [k]
    else:
        if v in cve_to_product.keys():
            cve_to_product[v].extend(k)
        else:
            cve_to_product[v] = [k]


insert_to_db(node_info, node_apps, node_ports, product_to_cve, total_cves)