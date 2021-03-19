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

### Updates
We are in the process of refining and releasing code on the repository, contact the authors for more details and updated information.
