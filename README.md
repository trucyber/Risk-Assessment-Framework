# Cyber-threats and Vulnerability Information Analyzer (CyVIA)
The standard risk assessment framework usually requires the use of tools or frameworks to collect data, followed by manual evaluation by cyber defenders to assess risk severity and determine if action needs to be taken. In contrast, CyVIA introduces a fully automated process that covers the entire risk assessment workflow, from data gathering to analysis generation. It enables continuous risk monitoring and provides threat-centric analytics that can adapt to changing network configurations without being restricted by time or space limitations. The key advantages of CyVIA include:

* Identify network and service dependencies within cyber infrastructures. 
* Evaluate individual nodes and the infrastructure as a whole for risk, taking into account implemented security controls and the risk from internal and external adversaries.
* Identify vulnerabilities within the operating systems and running applications of network nodes, and provide information on associated consequences and mitigation strategies.
* Classify the vulnerabilities based on the type of weakness, severity, and access vectors.
* Infrastructure-based top 10 most vulnerable products.
* Highlight products based on mean severity, vulnerability scores, and the number of vulnerabilities.
* Identify high-priority vulnerabilities and weakness types that defenders should prioritize for remediation.
* Generate relational analyses between the found vulnerabilities, products, and weakness types.
* Monitor for anomalous user activities based on recent adversarial trends.

### CyVIA Architecture:
<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/CyVIA_Full.png"><br>

### CyVIA Network Map
<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/network.PNG"><br>

### CyVIA Dependencies Map
<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/dependencies.PNG"><br>

### Results
We evaluate the proposed framework on a target network and discuss the derived results.

<img src="https://github.com/callmead/Risk-Assessment-VDB-Extension/blob/master/images/cve_relations.png"><br>

<img src="https://github.com/callmead/Risk-Assessment-VDB-Extension/blob/master/images/cwe-prods.png"><br>

<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/CVEs_share_top10.png"><br>

<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/CWEs_share_top10.png"><br>

### Setup Instructions:

You will need the following on your server machine:
* Graphviz 2.38 (should be available in the path environment variables)
* Flask 1.1.2 (for CyVIA API)
* Python 3
* CouchDB 3.1.1
* Jupyter Notebook

Requirements file:

aniso8601==8.0.0 <br />
certifi==2022.9.24 <br />
charset-normalizer==2.1.1 <br />
click==7.1.2 <br /> 
colorama==0.4.6 <br />
CouchDB==1.2 <br />
CouchDB2==1.13.0 <br />
Flask==1.1.2 <br />
Flask-RESTful==0.3.8 <br />
Flask-SQLAlchemy==2.4.3 <br />
idna==3.4 <br />
itsdangerous==1.1.0 <br />
Jinja2==2.11.2 <br />
joblib==1.2.0 <br />
lxml==4.9.1 <br />
MarkupSafe==1.1.1 <br />
numpy==1.23.4 <br />
pandas==1.5.1 <br />
pynput==1.7.6 <br />
python-dateutil==2.8.2 <br />
pytz==2020.1 <br />
requests==2.28.1 <br />
scipy==1.9.3 <br />
six==1.15.0 <br />
SQLAlchemy==1.3.18 <br />
tqdm==4.64.1 <br />
urllib3==1.26.12 <br />
Werkzeug==1.0.1 <br />

Jupyter Notebooks:
* 1_CWE_Master_Data_CouchDB.ipynb : Create Master Data for CWE referencing from MITRE.
* 2_Fetch_MITRE_CWE_CSV_Feeds.ipynb : Collect the latest CWE feeds from MITRE. 
* 3_Fetch_NVD_JSON_Feeds.ipynb : Collect vulnerability data from NVD.
* 4_Prepare_Dataset.ipynb : Compile collected files and prepare CyVIA knowledgebase based on the found relationships between the data. 
* 5_Network_Scanner.ipynb : Scans network for nodes and open ports.
* 6_Dependency_Mapper.ipynb : Maps service and network dependencies between the found network nodes.
* 7_Control_Mapper.ipynb : Evaluates network nodes for applied security controls.
* 8_Process_Monitor.ipynb : Monitors running processes on network nodes.
* 9_Scheduler.ipynb : Responsible for scheduling jobs to keep a check on updates and network activity.
* Node Analysis.ipynb : Evaluates each network node and prepares the detailed report for each node. 

Other Python files:
* cyvia_api.py : API file
* agent_linux_v2.py : CyVIA agent for Linux nodes to collect node information and pass it to server agent.
* agent_windows_v2.py : CyVIA agent for Windows nodes.
* client_scheduler_v2.py : CyVIA scheduler to keep the agent timely running and communicating with the server.
* server_scheduler_v2 : Server side scheduler to interact with client scheduler and keep the server up to date.
* config.py : Server configuration.
* functions.py : Functions library for CyVIA.
* get-pip.py : If pip is not installed on your machine, you can use this file.
* process_scanner_v2.py : Process scanner for network nodes, works with the client scheduler file.
* Spinner.py : On Python notebooks, if it takes a long time, the spinner spins to let the user know there is a process working in the background.

Script files:
* install_linux_req.sh : Installs required libraries on Linux network nodes for the agent to work.
* install_windows_req.bat : Installs required libraries on a Windows network node.
* linux_client_info.sh : Fetches Linux network node information for the Linux agent.
* win_client_info.psl : Fetches Windows network node information for the Windows agent. You may need to turn on the power shell execution on Windows nodes; see Turn on scripts on windows.txt.

Network setup:

We tested CyVIA on a simulated network environment. We have used VMWare and VirtualBox. All network nodes should be reachable for the framework to generate analysis.

### Execution Flow and Screenshots in action:
We are constantly working on improving and upgrading the CyVIA framework. Stable releases are made available on Github as soon as we finish testing. 

The general process flow is as follows:
* Deploy the agents on network nodes, and ensure all nodes have Python and required libraries installed. Run the schedulers on nodes, and the scan process will start. 
* On the server side, you may also run the server-side scheduler. Once the client and server-side schedulers communicate, the network node profiles will be created in the CyVIA knowledgebase.
* After this, the individual Jupyter Notebooks can be run on a need basis to see network analysis.


CouchDB

<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/CouchDB.PNG"><br>

Data collection from MITRE.

<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/CWE_Collection.PNG"><br>

Detailed information on CWEs.

<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/CWE_Details.PNG"><br>

CVE Data from NVD Feeds.

<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/NVD_Details.PNG"><br>

CyVIA Knowledge-base preparation. 

<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/Prepare_dataset.PNG"><br>

<!--- <img src=""><br> ---> 

Read more on CyVIA: 
* [Dynamic Vulnerability Classification for Enhanced Cyber Situational Awareness](https://ieeexplore.ieee.org/abstract/document/10131235) 
* [Dynamic Risk Assessment and Analysis Framework for Large-Scale Cyber-Physical Systems](https://eudl.eu/doi/10.4108/eai.25-1-2022.172997)
* [Robust Cyber-threat and Vulnerability Information Analyzer for Dynamic Risk Assessment](https://ieeexplore.ieee.org/abstract/document/9647584)
* [Quantitative Risk Modeling and Analysis for Large-Scale Cyber-Physical Systems](https://ieeexplore.ieee.org/abstract/document/9209654)

### Updates
We are in the process of refining and releasing code on the repository, contact the authors for more details and updated information.
