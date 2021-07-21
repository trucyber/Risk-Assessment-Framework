# Quantitative Risk Modeling and Analysis for Large-Scale Cyber-Physical Systems
Threats of cyber attacks are very real today and greatly impact everything including the public health sector, economics, electric grids, internet of things (IoT), and national security. The number of new evolving threats and reported vulnerabilities has severely increased in the last few years. Perpetually refined cyber-attacks have set data, organizational assets, organizations, and individuals at considerable risk. Protecting sophisticated networks and interdependent systems, or reducing the impact of cyber-attacks has become a major challenge, where today’s effective countermeasures can be completely ineffective tomorrow. The various risk assessment frameworks and methodologies are either high-level, missing risk metrics values, not suitable for all kinds of networks, or publicly not available. To address this issue, we present a quantitative risk assessment model, that helps to model the organizational security posture, evaluates the security controls in place, and provides an understanding of the associated risks. We further provide a detailed explanation of the formulations and evaluate the proposed model on an industrial scenario.

<img src="https://github.com/callmead/Risk-Assessment-Framework/blob/master/images/RA-IoT%20(2).png"><br>

Read more on: [https://ieeexplore.ieee.org/abstract/document/9209654](https://ieeexplore.ieee.org/abstract/document/9209654)

# Cyber-threats and Vulnerability Information Analyzer (CyVIA)
CyVIA can be used to extract, refine, merge, classify and utilize vulnerability information from two major vulnerability databases, NIST's NVD and MITRE's CVE.
We have used CyVIA to:
* Combine datasets from both NVD and CVE into a more descriptive vulnerability information system, 
* Identify vulnerabilities within a target network, and 
* Classify vulnerabilities based on vulnerability types, severity, products, and nodes. 

### CyVIA Architecture:
<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/Module_flow_2.png"><br>


### Target Network
<img src="https://github.com/callmead/Risk-Assessment-VDB-Extension/blob/master/images/Industrial_Network.png"><br>


### Results
We evaluate the proposed framework on a target network and discuss the derived results.

<img src="https://github.com/callmead/Risk-Assessment-VDB-Extension/blob/master/images/cve_relations.png"><br>

<img src="https://github.com/callmead/Risk-Assessment-VDB-Extension/blob/master/images/cwe-prods.png"><br>

<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/CVEs_share_top10.png"><br>

<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/CWEs_share_top10.png"><br>

### Setup Instructions:
* Python libraries: os, glob, requests, re, zipfile, timeit, json, csv, spacy
* Graphviz should also be available in the path environment variables. 

### Screen shots in action:
The programming language used is Python and we have used CouchDB as the backend. We are constantly upgrading the code, parts of the tool may not be available because of the continuous upgrades. As soon as we have a fully tested part, it will be available and screen shots will be provided as well.

CouchDB

<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/CouchDB.PNG"><br>

At first, we collect CWE data from MITRE.

<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/CWE_Collection.PNG"><br>

Then, we collect detailed information on these CWEs.

<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/CWE_Details.PNG"><br>

Next we collect CVE Data from NVD Feeds.

<img src="https://github.com/trucyber/Risk-Assessment-Framework/blob/master/images/NVD_Details.PNG"><br>

After this, we parepare the CyVIA Knowledge-base. 

<img src=""><br>

<!--- <img src=""><br> ---> 



### Updates
We are in the process of refining and releasing code on the repository, contact the authors for more details and updated information.
