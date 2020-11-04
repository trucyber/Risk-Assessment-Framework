#!/usr/bin/env python
# coding: utf-8

# NVD and MITRE Feed Handler...

# Imports
import json, csv, os, requests, re, zipfile, spacy, timeit, spacy
import pandas as pd  
from os import listdir
from os.path import isfile, join
from spacy.matcher import Matcher

# global variables...
json_files_path = 'nvd_json_files'
analysis_path = 'analysis'
summarized_dataset = analysis_path + '/' + 'CyVID_dataset.csv'

mitre_csv_path = 'mitre_csv_files/Combined_CWE.csv'
cwe_data = pd.read_csv(mitre_csv_path) # load cwe data file in dataframs

enc = 'utf-8' # enc = 'utf-16', enc = 'iso-8859-15', enc = 'cp437'

# 1. Check existing files and folders
def check_files(dir_path):
    # Check if the directory for json files exists, if not create one.
    if (os.path.isdir(os.getcwd()+'\\'+dir_path)): # if folder does not exist, create one
        print('Directory',dir_path,'already exists.')
        # remove old files from the directory
        print('Removing old files...', end=' ')
        files = glob.glob(os.getcwd()+'\\'+dir_path+'\\*')
        for f in files:
            os.remove(f)
        print('Done.\n')
    else:
        print('Creating directory',dir_path, 'to store analysis.', end=' ')
        directory = os.path.join(os.getcwd()+'\\' + dir_path) 
        os.mkdir(directory)
        print('Done.\n')

# 2. Prepare data from downloaded JSON files...
# This step reads the JSON files and writes the collected data to a CSV file. 
def read_and_summarize():
    print('Step 3: Reading and summarizing NVD JSON files.')
    # Start writing new file...
    # writing a clean CSV file...
    with open(summarized_dataset, 'w', newline='') as file:
        writer = csv.writer(file)
        # write the header...
        writer.writerow(['CVE_ID','Lang', 'CWE_ID', 'CWE_Desc', 'CWE_Plat', 'CWE_Af_Res', 'Severity', 'CVSS_V2', 'CVSS_V3', 'Vul_Access_Vector', 'UserInteractionReq', 'OS', 'SW', 'Ports', 'PublishedDate','LastModified','Description', 'URL&Tags'])
        # data field variables as above line
        CVE_ID, CVE_Lang, CWE_ID, CWE_Desc, CWE_Plat, CWE_Af_Res, CVE_Sev, CVSS_V2, CVSS_V3, CVE_VAV, CVE_UIR, CVE_PD, CVE_MD, CVE_Desc="","","","","","","","","","","","","",""
        CVE_OS, CVE_SW, CVE_Ports = [], [], [] # Lists
        # missing data field counters
        M_CVE_Lang, M_CWE_ID, M_CWE_ID_Other, M_CWE_ID_Other2, M_CWE_Desc, M_CWE_Plat, M_CWE_Af_Res, M_CVE_Sev, M_CVSS_V2, M_CVSS_V3, M_CVE_VAV, M_CVE_UIR, M_OS, M_SW, M_Ports, M_CVE_PD, M_CVE_MD, unicode_error=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        vul_info_counter=0 # total number of handled vulnerabilities
        
        #Loop through input files in the directory...
        for root, dirs, files in os.walk(json_files_path + '/', topdown=False):
            for name in files:
                with open(os.path.join(root, name), 'r', encoding=enc) as f:
                    print('Reading from', os.path.join(root, name)+'...', end='')
                    data=json.load(f)

                #Write json file data as rows to the new file...
                print(' Writing to '+ summarized_dataset)
                for i in range(0, len(data['CVE_Items'])):
                    vul_info_counter+=1 # increment vul counter
                    # extract URL and Tag references 
                    url_tag_dict = {}
                    # collecting references, can be more than one.
                    for x in range(0, len(data['CVE_Items'][i]['cve']['references']['reference_data'])): # first item till the last item.
                        url_tag_dict['URL'+str(x)] = data['CVE_Items'][i]['cve']['references']['reference_data'][x]['url'] # append dict.
                        # for tag list, add more than one tags.
                        for y in range(0, len(data['CVE_Items'][i]['cve']['references']['reference_data'][x]['tags'])): 
                            url_tag_dict['URL'+str(x)+'-Tag'+str(y)] = data['CVE_Items'][i]['cve']['references']['reference_data'][x]['tags'][y]             

                    # Fetching field[i]values from JSON file
                    # Field: CVE_ID, CVE-Description, available for all entries.
                    CVE_ID = data['CVE_Items'][i]['cve']['CVE_data_meta']['ID']
                    CVE_Desc = data['CVE_Items'][i]['cve']['description']['description_data'][0]['value']

                    # Extract keywords from the above description
                    CVE_OS, CVE_SW, CVE_Ports = [], [], []
                    CVE_OS, CVE_SW, CVE_Ports = fetch_keywords(str(CVE_Desc))

                    try: # Field: CVE-Language
                        CVE_Lang = data['CVE_Items'][i]['cve']['problemtype']['problemtype_data'][0]['description'][0]['lang'] #CVE Language
                    except IndexError: # Some CVEs are missing Vuln Type and Lang values.
                        CVE_Lang = "N/A"
                        M_CVE_Lang+=1

                    try: # Field: CWE-ID
                        CWE_ID = data['CVE_Items'][i]['cve']['problemtype']['problemtype_data'][0]['description'][0]['value'] #CVE Type
                        # Counting CWEs with values NVD-CWE-Other and NVD-CWE-noinfo
                        if CWE_ID == 'NVD-CWE-Other':
                            M_CWE_ID_Other+=1
                            CWE_Desc, CWE_Plat, CWE_Af_Res = "N/A", "N/A", "N/A"
                            M_CWE_Desc, M_CWE_Plat, M_CWE_Af_Res = (M_CWE_Desc+1), (M_CWE_Plat+1), (M_CWE_Af_Res+1) # increment counters 
                        elif CWE_ID == 'NVD-CWE-noinfo':
                            M_CWE_ID_Other2+=1
                            CWE_Desc, CWE_Plat, CWE_Af_Res = "N/A", "N/A", "N/A"
                            M_CWE_Desc, M_CWE_Plat, M_CWE_Af_Res = (M_CWE_Desc+1), (M_CWE_Plat+1), (M_CWE_Af_Res+1) # increment counters                            
                        else: # when CWE-ID is an actual number
                            CWE_Desc, CWE_Plat, CWE_Af_Res = fetch_cwe_data(CWE_ID) # fetch CWE Data from CWE File.
                            
                    except IndexError: # Some CVEs are missing Vuln Type and Lang values.
                        # CWE_ID = "N/A" # this is not required. 
                        M_CWE_ID+=1

                    try: # Field: severity
                        CVE_Sev = data['CVE_Items'][i]['impact']['baseMetricV2']['severity']
                    except KeyError: # Reserved CVEs will have this field value missing
                        CVE_Sev = "N/A"
                        M_CVE_Sev+=1

                    try: # Field: V2 Score
                        CVSS_V2 = data['CVE_Items'][i]['impact']['baseMetricV2']['cvssV2']['baseScore']
                    except KeyError: # Reserved CVEs will have this field value missing
                        CVSS_V2 = -1
                        M_CVSS_V2+=1

                    try: # Field: CVSS Score V3, not all CVEs have CVSS v3 Scores so we keep rest as zero.
                        CVSS_V3 = data['CVE_Items'][i]['impact']['baseMetricV3']['cvssV3']['baseScore']
                    except KeyError:
                        CVSS_V3 = -1
                        M_CVSS_V3+=1

                    try: # Field: accessVector, not all CVEs have CVSS v3 Scores so we keep rest as zero.
                        CVE_VAV = data['CVE_Items'][i]['impact']['baseMetricV2']['cvssV2']['accessVector']
                    except KeyError:
                        CVE_VAV = "N/A"
                        M_CVE_VAV+=1

                    try: # Field: userInteractionRequired, not all CVEs have CVSS v3 Scores so we keep rest as zero.
                        CVE_UIR = data['CVE_Items'][i]['impact']['baseMetricV2']['userInteractionRequired']
                    except KeyError:
                        CVE_UIR = "N/A"
                        M_CVE_UIR+=1                    

                    try: # Field: publishedDate, not all CVEs have CVSS v3 Scores so we keep rest as zero.
                        CVE_PD = data['CVE_Items'][i]['publishedDate']
                    except KeyError:
                        CVE_PD = "N/A"
                        M_CVE_PD+=1 

                    try: # Field: lastModifiedDate, not all CVEs have CVSS v3 Scores so we keep rest as zero.
                        CVE_MD = data['CVE_Items'][i]['lastModifiedDate']
                    except KeyError:
                        CVE_MD = "N/A"
                        M_CVE_MD+=1 

                    # Write row to the output CVS file...
                    print(CVE_ID, end=' ') #Currently processing CVE_ID
                    try:
                        writer.writerow([CVE_ID, CVE_Lang, CWE_ID, CWE_Desc, CWE_Plat, CWE_Af_Res, CVE_Sev, CVSS_V2, 
                            CVSS_V3, CVE_VAV, CVE_UIR, CVE_OS, CVE_SW, CVE_Ports, CVE_PD, CVE_MD, CVE_Desc, 
                            json.dumps(url_tag_dict)])
                    except UnicodeEncodeError: # may occure for description field
                        writer.writerow([CVE_ID, CVE_Lang, CWE_ID, CWE_Desc, CWE_Plat, CWE_Af_Res, CVE_Sev, CVSS_V2, 
                            CVSS_V3, CVE_VAV, CVE_UIR, CVE_OS, CVE_SW, CVE_Ports, CVE_PD, CVE_MD, 
                            CVE_Desc.encode("utf-8"), json.dumps(url_tag_dict)])
                        unicode_error+=1

    print('Step 2 complete.')
    print('\nTotal number of vulnerability records found:',vul_info_counter, '\nVulnerabilities with missing information:')
    print('Lang:\t\t'+str(M_CVE_Lang)+'\n\nCWE-ID:\t\t'+str(M_CWE_ID)+'\nNVD-CWE-Other\t'+str(M_CWE_ID_Other)+
          '\nNVD-CWE-noinfo:\t'+str(M_CWE_ID_Other2)+'\nTotal CWE:\t'+str(M_CWE_ID+M_CWE_ID_Other+M_CWE_ID_Other2)+
          '\n\nSeverity:\t'+str(M_CVE_Sev)+'\nCVSS_V2:\t'+str(M_CVSS_V2)+
          '\nCVSS_V3:\t'+str(M_CVSS_V3)+'\nVul_access:\t'+str(M_CVE_VAV)+'\nUserIntReq:\t'+str(M_CVE_UIR)+'\nPublishDate:\t'+
          str(M_CVE_PD)+'\nModifiedDate:\t'+str(M_CVE_MD)+'\nUnicodeError:\t'+str(unicode_error))
    print('\nCWE_Desc:\t'+str(M_CWE_Desc)+'\nCWE_Plat:\t'+str(M_CWE_Plat)+'\nCWE_Af_Res:\t'+str(M_CWE_Af_Res)+
          '\nM_OS:\t\t'+str(M_OS)+'\nM_SW:\t\t'+str(M_SW)+'\nM_Ports:\t'+str(M_Ports))
    print('\n')
    # End 2. Prepare data from downloaded JSON files...

# **************************************************************
# 3. Fetch OS, SW Versions, and Port Numbers from given CVE Description...
nlp = spacy.load('en_core_web_sm')
def fetch_keywords(text):
    # extract port numbers from text
    port_list = find_ports_from_text(text)
    
    # extract sw and os related terms.
    match_list = []
    patterns = [
                [{'POS': 'PROPN'}, {'POS': {"IN": ["PROPN","NUM", "X", "VERB"]}}],
                [{'POS': 'PROPN'}, {'POS': 'PROPN'}, {'POS': {"IN": ["NUM","X","VERB"]}}],    
               ]
    matcher = Matcher(nlp.vocab)
    matcher.add("PROPN-PROPN-NUM", None, patterns[0])
    matcher.add("PROPN-PROPN-VERB", None, patterns[1])
    doc = nlp(text)
    matches = matcher(doc)
    for match_id, start, end in matches:
        string_id = nlp.vocab.strings[match_id]
        span = doc[start:end]
        match_list.append(span.text)
    
    # Remove duplicates from the list
    match_list = list(dict.fromkeys(match_list))
    
    # Remove subsets from the list ['Microsoft Windows 2000', 'Windows 2000']
    for m in match_list:
        for n in match_list:
            if (len(m) > len(n)) and (set(n).issubset(set(m))):
                match_list.remove(n)
    
    # Extract OS from the list...
    os_list = [idx for idx in match_list if 
            idx.lower().startswith('Microsoft'.lower()) or idx.lower().startswith('Windows'.lower()) or 
            idx.lower().startswith('Ubuntu'.lower()) or idx.lower().startswith('Linux'.lower()) or 
            idx.lower().startswith('Apple'.lower()) or idx.lower().startswith('macOS'.lower()) or 
            idx.lower().startswith('RedHat'.lower()) or idx.lower().startswith('Red Hat'.lower()) or 
            idx.lower().startswith('CentOS'.lower()) or idx.lower().startswith('Fedora'.lower()) or 
            idx.lower().startswith('openSUSE'.lower())
          ] 

    # Extract SW names from the list...
    sw_list = []
    for elem in match_list:
        if elem not in os_list:
            sw_list.append(elem) 
    return os_list, sw_list, port_list


# 4. Port extractor from string... 
def find_ports_from_text(text):
    port_list = []
    nlp = spacy.load('en', disable=['parser', 'tagger', 'ner'])
    doc = nlp(text)
    port_pattern = re.compile(r"[Pp](ort)[s]? [:]?(\d+)?((\d+|less than | and |, |,|/|/ | / | |-)?(\d+))*") #  

    for match in re.finditer(port_pattern, doc.text):
        start, end = match.span()
        # if text is only 'port ' then discard it
        if doc.text[start:end].lower() != 'port ' or doc.text[start:end].lower() != 'ports ': 
            # print(f"Ports available: '{doc.text[start:end]}'")
            port_list.append(doc.text[start:end])
        span = doc.char_span(start, end)
    return port_list


# 5. Referencing CWE File for fetching CWE Descriptions and related data...
# This step reads the JSON files and writes the collected data to a CSV file.
# Extracting 'CWE_Desc', 'CWE_Plat', 'CWE_Af_Res'
def fetch_cwe_data(given_cwe_id): 
    # strip CWE- from the given cwe id
    CWE_ID_No = (given_cwe_id.replace('CWE-', ''))
    result = cwe_data.loc[cwe_data['CWE-ID'] == int(CWE_ID_No)]
    CWE_Description = result.iloc[0,1]
    CWE_App_Plat = result.iloc[0,8]
    CWE_Aff_Res = result.iloc[0,19]
    return CWE_Description, CWE_App_Plat, CWE_Aff_Res 


print('*** Dataset Preparation v3 ***\n')
# time the execution
start = timeit.default_timer() # start timer
# Step 1, Check files and directories
check_files(analysis_path);

# Step 2, read JSON files, summarize data and extract keywords...
read_and_summarize()
# Step 3 and 4 will execute based on current CWE-ID and CVE-Description, therefore it will run within Step 2.

stop = timeit.default_timer()
execution_time = stop - start
print("Program Executed in "+str(execution_time)) # It returns time in seconds
