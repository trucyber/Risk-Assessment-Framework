import joblib, re, nltk, json, couchdb2, spacy
import xgboost as xgb
import pandas as pd
import numpy as np

# summarize text
from spacy.lang.en.stop_words import STOP_WORDS
from string import punctuation
from heapq import nlargest
# others 
from urllib.request import urlopen
from xgboost import XGBClassifier
from nltk import word_tokenize
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
nltk.download('stopwords')
from sklearn.feature_extraction.text import CountVectorizer, TfidfTransformer, TfidfVectorizer, CountVectorizer
from flask import Flask, jsonify
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from multiprocessing.pool import ThreadPool
from flask import Flask, redirect, url_for, render_template, request, flash

import warnings # ignore pandas warnings
warnings.filterwarnings("ignore")

app = Flask(__name__)
api = Api(app)
db_user, db_pass, db_host, db_port = 'admin', 'Samsung_1234', 'localhost', '5984'
server = couchdb2.Server("http://%s:%s@%s:%s" % (db_user, db_pass, db_host, db_port))
if server.up(): # if server is up and ready
    x, y = 'CouchDB ('+str(server.version)+') up and running with ('+str(len(server))+') user defined databases.', 'Databases include:'
    for dbname in server:
        y = y + ' ' + str(dbname)
    x = x + ' ' + y
else:
    x = 'CouchDB not reachable'
print('\nstatus:', x)
print()

@app.route("/")
def index():
	return render_template("index.html")

# Global Functions...
''' nlp = spacy.load('en_core_web_sm')
    doc= nlp(text)
    tokens=[token.text for token in doc]
    word_frequencies={}
    for word in doc:
        if word.text.lower() not in list(STOP_WORDS):
            if word.text.lower() not in punctuation:
                if word.text not in word_frequencies.keys():
                    word_frequencies[word.text] = 1
                else:
                    word_frequencies[word.text] += 1
    max_frequency=max(word_frequencies.values())
    for word in word_frequencies.keys():
        word_frequencies[word]=word_frequencies[word]/max_frequency
    sentence_tokens= [sent for sent in doc.sents]
    sentence_scores = {}
    for sent in sentence_tokens:
        for word in sent:
            if word.text.lower() in word_frequencies.keys():
                if sent not in sentence_scores.keys():                            
                    sentence_scores[sent]=word_frequencies[word.text.lower()]
                else:
                    sentence_scores[sent]+=word_frequencies[word.text.lower()]
    select_length=int(len(sentence_tokens)*per)
    summary=nlargest(select_length, sentence_scores,key=sentence_scores.get)
    final_summary=[word.text for word in summary]
    summary=''.join(final_summary)
    return summary '''
def text_summarize(text, per):
    nlp = spacy.load('en_core_web_sm')
    doc = nlp(text)
    sentences = [sent for sent in doc.sents]
    words = [word.text.lower() for word in doc if not word.is_stop and not word.is_punct]
    word_frequencies = {word: words.count(word) / len(words) for word in set(words)}
    sentence_scores = {sent: sum(word_frequencies.get(word.text.lower(), 0) for word in sent) for sent in sentences}
    summary = ''.join([sent.text for sent in nlargest(int(len(sentences) * per), sentence_scores, key=sentence_scores.get)])
    return summary    
    
def find_cve_info(cve_id):
    db_name = 'cyvia_dataset'
    db = server[db_name] # select database
    full_data_mitre, short_data_mitre, cyvia_data = {}, {}, {}
    found_con, found_mit, mitre_url = False, False, False
    
    cve_details_url = "https://cveawg.mitre.org/api/cve/"+cve_id
    # get MITRE API results on the CVE
    try:
        response = urlopen(cve_details_url)
        full_data_mitre = json.loads(response.read())  
        mitre_url = True
    except:
        print('MITRE URL failed')
        full_data_mitre[cve_id], short_data_mitre[cve_id] = "CVE not found", "CVE not found"
        pass
        
    # find values for these keys from data
    scope_lookup, note_lookup, strategy_lookup, desc_lookup = 'IMPACT', 'NOTE', 'STRATEGY', 'DESCRIPTION'
    
    if cve_id in db:
        cyvia_data[cve_id] = {}
        
        # MITRE information
        if mitre_url: #  and cve_id not in short_data_mitre
            # get product version(s)
            prod_vers, prob_types = [], []
            try:
                for v in range(0, len(full_data_mitre['containers']['cna']['affected'][0]['versions'])):
                    prod_vers.append(full_data_mitre['containers']['cna']['affected'][0]['versions'][v]['version']) 
            
                for p in range(0, len(full_data_mitre['containers']['cna']['problemTypes'])):
                    for pd in range(0, len(full_data_mitre['containers']['cna']['problemTypes'][p]['descriptions'])):
                        prob_types.append(full_data_mitre['containers']['cna']['problemTypes'][p]['descriptions'][pd]['description'])
            
                cyvia_data[cve_id]['description'] = full_data_mitre['containers']['cna']['descriptions'][0]['value']
                cyvia_data[cve_id]['vendor'] = full_data_mitre['containers']['cna']['affected'][0]['vendor']
                cyvia_data[cve_id]['affected_product'] = full_data_mitre['containers']['cna']['affected'][0]['product']
                cyvia_data[cve_id]['problem_type(s)'] = prob_types                
                cyvia_data[cve_id]['version(s)'] = prod_vers
                        
            except KeyError: 
                print('Missing information at MITRE for CVE', cve_id)
                cyvia_data[cve_id]['description'] = db[cve_id]['description']
                pass                

        # Consequences Scope, Impact and notes.
        if db[cve_id]['cwe_consequences'] != {}:
            found_con = True
            x=[]
            for key in db[cve_id ]['cwe_consequences'].keys():
                x.append(key)                
            cyvia_data[cve_id]['Target(T)'] = [*set(x)]
            # get all impact values for target
            item_impact = [val[scope_lookup] for key, val in db[cve_id]['cwe_consequences'].items() if scope_lookup in val]
            item_impact = [i for sublist in item_impact for i in sublist] # make one list, remove sublists
            cyvia_data[cve_id]['T_Impact(TI)'] = [*set(item_impact)] # remove duplicates
            # Notes
            item_notes = [val[note_lookup] for key, val in db[cve_id]['cwe_consequences'].items() if note_lookup in val]
            item_notes = [i for sublist in item_notes for i in sublist] # make one list, remove sublists
            # if len(item_notes)!=0: cyvia_data[cve_id]['TI_Notes'] = item_desc # [:2] show first 2 only
        
        # Mitigation, prevention, strategies and descriptions.
        if db[cve_id]['cwe_mitigations'] != {}:
            found_mit = True
            x=[]
            for key in db[cve_id]['cwe_mitigations'].keys():
                x.append(key)
            cyvia_data[cve_id]['Prevent(P)'] = [*set(x)]
            item_strategy = [val[strategy_lookup] for key, val in db[cve_id]['cwe_mitigations'].items() if strategy_lookup in val]
            item_strategy = [i for sublist in item_strategy for i in sublist] # make one list, remove sublists
            if len(item_strategy)!=0: cyvia_data[cve_id]['P_Strategy(PS)'] = [*set(item_strategy)] # remove duplicates [*set(item_strategy)]
            # Descriptions
            item_desc = [val[desc_lookup] for key, val in db[cve_id]['cwe_mitigations'].items() if desc_lookup in val]
            item_desc = [i for sublist in item_desc for i in sublist] # make one list, remove sublists
            if len(item_desc)!=0: cyvia_data[cve_id]['PS_Details'] = item_desc # [:2] show first 2 only
        
        # If nothing found
        if found_con==False and found_mit==False: cyvia_data[cve_id] = "No consequences or mitigation information found"

    else:
        print('Missing information in CyVIA dataset for CVE', cve_id)
        cyvia_data[cve_id] = "CVE not found in CyVIA dataset!"

    #print(json.dumps(cyvia_data, indent=2))
    return cyvia_data

def find_mitigation(lookupitems):
    mitigation_data = {}
    no_con_mit_count = 0
    vendors, affected_products, problem_types, targets, impacts, prevents, p_strategies, p_details = [],[],[],[],[],[],[],[]
    for cve_id in lookupitems:
        cyvia_data = find_cve_info(cve_id)
        # print(json.dumps(cyvia_data, indent=2))
        if cyvia_data[cve_id] == "No consequences or mitigation information found": 
            no_con_mit_count+=1
            continue
        
        if 'vendor' in cyvia_data[cve_id]: 
            if (cyvia_data[cve_id]['vendor'] != 'n/a'): 
                vendors.append(cyvia_data[cve_id]['vendor'])
        if 'affected_product' in cyvia_data[cve_id]: 
            if (cyvia_data[cve_id]['affected_product'] != 'n/a'): 
                affected_products.append(cyvia_data[cve_id]['affected_product'])
        if 'problem_type(s)' in cyvia_data[cve_id]: 
            if (cyvia_data[cve_id]['problem_type(s)'] != ['n/a']): 
                problem_types.extend(cyvia_data[cve_id]['problem_type(s)'])

        if 'Target(T)' in cyvia_data[cve_id]: targets.extend(cyvia_data[cve_id]['Target(T)'])
        if 'T_Impact(TI)' in cyvia_data[cve_id]: impacts.extend(cyvia_data[cve_id]['T_Impact(TI)'])
        if 'Prevent(P)' in cyvia_data[cve_id]: prevents.extend(cyvia_data[cve_id]['Prevent(P)'])
        if 'P_Strategy(PS)' in cyvia_data[cve_id]: p_strategies.extend(cyvia_data[cve_id]['P_Strategy(PS)'])
        if 'PS_Details' in cyvia_data[cve_id]: p_details.extend(cyvia_data[cve_id]['PS_Details'])
    
    print('\nVendors *', len([*set(vendors)]), ':', [*set(vendors)])
    print('\nAffected Products *', len([*set(affected_products)]), ':',[*set(affected_products)])
    # print('\nProblem Types:', [*set(problem_types)]) # not needed for now
    
    print('\nTargets *', len([*set(targets)]), ':', [*set(targets)])
    print('\nImpacts *', len([*set(impacts)]), ':', [*set(impacts)])
    print('\nPreventions(P) *', len([*set(prevents)]), ':', [*set(prevents)])
    print('\nP_Strategies(PS) *', len([*set(p_strategies)]), ':', [*set(p_strategies)])
    print('\nNo con and mit found for', no_con_mit_count, 'CVE(s). \nPreparing prevention strategies...')
    
    # summarize PS_details
    p_dets_short = []
    ps_dets = [*set(p_details)]
    for i in range(len(ps_dets)):
        x = text_summarize(ps_dets[i], 0.25) # summarize ratio 25%
        if x != '': p_dets_short.append(x) # if text is long enough and short summary is generated
        else: p_dets_short.append(ps_dets[i])    
    print('\nPS_Details:', *p_dets_short, sep = '\n')
    return [*set(vendors)], [*set(affected_products)], [*set(problem_types)], [*set(targets)], [*set(impacts)], [*set(prevents)], [*set(p_strategies)], p_dets_short

    
def get_cve_info(cve_id):
    db_name = 'cyvia_dataset'
    db = server[db_name] # select database

    
    full_data_mitre, short_data_mitre, cyvia_data = {}, {}, {}
    found_con, found_mit, mitre_url = False, False, False
    
    cve_details_url = "https://cveawg.mitre.org/api/cve/"+cve_id
    # get MITRE API results on the CVE
    try:
        response = urlopen(cve_details_url)
        full_data_mitre = json.loads(response.read())  
        mitre_url = True
    except:
        print('MITRE URL failed')
        full_data_mitre[cve_id], short_data_mitre[cve_id] = "CVE not found", "CVE not found"
        pass
        
    # find values for these keys from data
    scope_lookup, note_lookup, strategy_lookup, desc_lookup = 'IMPACT', 'NOTE', 'STRATEGY', 'DESCRIPTION'
    
    if cve_id in db:
        cyvia_data[cve_id] = {}
        
        # MITRE information
        if mitre_url: #  and cve_id not in short_data_mitre
            # get product version(s)
            prod_vers, prob_types = [], []
            try:
                for v in range(0, len(full_data_mitre['containers']['cna']['affected'][0]['versions'])):
                    prod_vers.append(full_data_mitre['containers']['cna']['affected'][0]['versions'][v]['version']) 
            
                for p in range(0, len(full_data_mitre['containers']['cna']['problemTypes'])):
                    for pd in range(0, len(full_data_mitre['containers']['cna']['problemTypes'][p]['descriptions'])):
                        prob_types.append(full_data_mitre['containers']['cna']['problemTypes'][p]['descriptions'][pd]['description'])
            
                cyvia_data[cve_id]['description'] = full_data_mitre['containers']['cna']['descriptions'][0]['value']
                cyvia_data[cve_id]['vendor'] = full_data_mitre['containers']['cna']['affected'][0]['vendor']
                cyvia_data[cve_id]['affected_product'] = full_data_mitre['containers']['cna']['affected'][0]['product']
                cyvia_data[cve_id]['problem_type(s)'] = prob_types                
                cyvia_data[cve_id]['version(s)'] = prod_vers
                        
            except KeyError: 
                print('Missing information at MITRE for CVE', cve_id)
                cyvia_data[cve_id]['description'] = db[cve_id]['description']
                pass                

        # Consequences Scope, Impact and notes.
        if db[cve_id]['cwe_consequences'] != {}:
            found_con = True
            x=[]
            for key in db[cve_id ]['cwe_consequences'].keys():
                x.append(key)                
            cyvia_data[cve_id]['Target(T)'] = [*set(x)]
            # get all impact values for target
            item_impact = [val[scope_lookup] for key, val in db[cve_id]['cwe_consequences'].items() if scope_lookup in val]
            item_impact = [i for sublist in item_impact for i in sublist] # make one list, remove sublists
            cyvia_data[cve_id]['T_Impact(TI)'] = [*set(item_impact)] # remove duplicates
            # Notes
            item_notes = [val[note_lookup] for key, val in db[cve_id]['cwe_consequences'].items() if note_lookup in val]
            item_notes = [i for sublist in item_notes for i in sublist] # make one list, remove sublists
            # if len(item_notes)!=0: cyvia_data[cve_id]['TI_Notes'] = item_desc # [:2] show first 2 only
        
        # Mitigation, prevention, strategies and descriptions.
        if db[cve_id]['cwe_mitigations'] != {}:
            found_mit = True
            x=[]
            for key in db[cve_id]['cwe_mitigations'].keys():
                x.append(key)
            cyvia_data[cve_id]['Prevent(P)'] = [*set(x)]
            item_strategy = [val[strategy_lookup] for key, val in db[cve_id]['cwe_mitigations'].items() if strategy_lookup in val]
            item_strategy = [i for sublist in item_strategy for i in sublist] # make one list, remove sublists
            if len(item_strategy)!=0: cyvia_data[cve_id]['P_Strategy(PS)'] = [*set(item_strategy)] # remove duplicates [*set(item_strategy)]
            # Descriptions
            item_desc = [val[desc_lookup] for key, val in db[cve_id]['cwe_mitigations'].items() if desc_lookup in val]
            item_desc = [i for sublist in item_desc for i in sublist] # make one list, remove sublists
            if len(item_desc)!=0: cyvia_data[cve_id]['PS_Details'] = item_desc # [:2] show first 2 only
        
        # If nothing found
        if found_con==False and found_mit==False: cyvia_data[cve_id] = "No consequences or mitigation information found"

    else:
        print('Missing information in CyVIA dataset for CVE', cve_id)
        cyvia_data[cve_id] = "CVE not found in CyVIA dataset!"

    #print(json.dumps(cyvia_data, indent=2))
    return cyvia_data

def classify_cve_description(desc):
    print('\n** Description:', desc, '**\n')
    model = joblib.load('LinearSVC().pkl')
    dataset_labels = ['unknown attack', 'buffer overflow', 'denial of service', 'unauthorized access', 'code injection', 'cross-site scripting', 'server-side request forgery', 'memory based attack', 'credentials', 'command and control', 'directory traversal', 'brute force attack', 'man-in-the-middle', 'privilege escalation', 'disabling security tools', 'sensitive data exposure', 'network sniffing', 'host redirection', 'system misconfiguration', 'web session cookie']

    # Preprocess...
    # Remove stop words
    # nltk.download('stopwords') # downloaded at import time.
    text_tokens = word_tokenize(desc)
    tokens_without_sw = [word for word in text_tokens if not word in stopwords.words()]
    filtered_sentence = (" ").join(tokens_without_sw)
    
    stemmer = WordNetLemmatizer()
    # Substituting multiple spaces with single space
    document = re.sub(r'\s+', ' ', filtered_sentence, flags=re.I)
    print('** Trimmed description:', document, '**')

    tfidfconverter = TfidfTransformer()
    loaded_vec = CountVectorizer(decode_error="replace",vocabulary=joblib.load(open('Vectorizer.pkl','rb')))
    features = tfidfconverter.fit_transform(loaded_vec.fit_transform(np.array([document])))

    y_predict = model.predict(features)
    attack_type = dataset_labels[y_predict[0]]
    # print('** Prediction:', attack_type, '**\n')
    return attack_type
    
    
# End Global Functions...    

# Check the couchdb server atatus if up and running.
class CyVIA(Resource): 
    def get(self):
        return jsonify({"message": x})

''' Authentication Process
class Authenticate(Resource):
    def get(self, attached_data):
        db_name = 'cyvia_users'
        db = server[db_name] # select database
        attached_doc = json.loads(attached_data) # make json of attached data
        print(attached_doc)
        
        for doc in db:
            if doc['user']==attached_doc['user']: # if user = provided username
                if doc['pass']==attached_doc['pass']:
                    print('Authentication: Sucessful')
                    return {"message":"sucess"}
                else:
                    print('Authentication: Invalid password')
                    return {"message":"invalid password"}
            else:
                print('Authentication: Invalid username')
                return {"message":"invalid user"}
'''

# Add/Update/Delete/Query CouchDB Server        
class CyVIA_functions(Resource):            
    def get(self, db_operation, db_name, attached_data):
        # Check if DB exists
        if db_name in server: # already existing database # if db.exists():
            print('\n*** Valid database ('+db_name+') selected.')
            db = server[db_name] # select database
            attached_doc = json.loads(attached_data) # make json of attached data
            
            # Function add
            if (db_operation == "add"):
                print('\n*** Inserting doc:\n'+json.dumps(attached_doc, indent=4))
                db.put(attached_doc)
                return {"operation": db_operation, "database": db_name, "doc": json.loads(attached_data), "status": "sucessfully added"}
     
            # Function update
            elif (str(db_operation) == "update"):
                print('\n*** Updating doc:\n'+json.dumps(attached_doc, indent=4))
                db.put(attached_doc)
                return {"operation": db_operation, "database": db_name, "attached_data": json.loads(attached_data), "status": "sucessfully updated"}
            
            # Function delete
            elif (db_operation == "delete"):
                print('\n*** Deleting doc:\n'+json.dumps(attached_doc, indent=4))
                db.delete(attached_doc)
                return {"operation": db_operation, "database": db_name, "attached_data": json.loads(attached_data), "status": "sucessfully deleted"}
            
            elif(db_operation == "addapps"):
                #print('\n*** Updating doc:\n'+json.dumps(attached_doc, indent=4))
                if attached_doc['_id'] in db:
                    doc = db[attached_doc['_id']]
                    if 'applications' in doc:
                        print(doc['applications'])
                        #print('Found applications', len(doc['applications']), type(doc['applications']))
                        doc['applications'].append(attached_doc['applications'])
                        print(doc['applications'])
                        new_doc = {"_id":doc['_id'], "_rev":doc['_rev'],"HostName":doc['HostName'], "HostIP":doc['HostIP'], "HostGateway":doc['HostGateway'], "HostOS":doc["HostOS"], "applications":doc['applications']}
                    else:
                        print('add applications')
                        print('add', attached_doc['applications'])
                        new_doc = {"_id":doc['_id'], "_rev":doc['_rev'], "HostName":doc['HostName'], "HostIP":doc['HostIP'], "HostGateway":doc['HostGateway'], "HostOS":doc["HostOS"], "applications":[attached_doc['applications']]}

                    db.put(new_doc)
                    return {"operation": db_operation, "database": db_name, "attached_data": json.loads(attached_data), "status": "sucessfully added"}
                else:
                    print('\n*** Document with _id not found')
                    return {"operation": db_operation, "database": db_name, "attached_data": json.loads(attached_data), "status": "document with _id not found"}
                #print(attached_doc['applications'], len(attached_doc['applications']))
                return {"a": "a"}
                #db.put(attached_doc)
                #return {"operation": db_operation, "database": db_name, "attached_data": json.loads(attached_data), "status": "sucessfully added"}
            # Function add apps to a noded
            #elif (str(db_operation == "addapps")):
            #    print('\n*** Updating doc:\n'+json.dumps(attached_doc, indent=4))
        

            # Function query
            elif (db_operation == "query"):
                if (len(db) >= 1): # if documents exist in db then query
                    result = [] # documents dictionary
                    if attached_data == '{"all":"docs"}': # if requested all docs
                        for doc in db:
                            print('\n*** Found doc with rev:', doc['_rev'])
                            print(json.dumps(doc, indent=4))
                            result.append(doc)    
                        return {"operation": db_operation, "database": db_name, "attached_data": json.loads(attached_data), "status": "found "+str(len(result)), "doc(s)": result}                
                    
                    else: # find docs with keyword
                        for key, value in attached_doc.items():
                            print('\n*** Looking for key:', key, 'with value:', value)
                        
                            doc_found=False
                            for doc in db:
                                try:
                                    if doc[key]==value: # if document has key value pair
                                        print('\n*** Found doc with rev:', doc['_rev'])
                                        print(json.dumps(doc, indent=4))
                                        doc_found=True
                                        result.append(doc) # Add doc to result dictionary
                                        
                                except KeyError: # ignore documents that do not have key
                                    pass
                            if doc_found==False: 
                                print('\n*** Document not found!')
                                return {"operation": db_operation, "database": db_name, "attached_data": json.loads(attached_data), "status": "no documents found in "+db_name}
                            else:
                                return {"operation": db_operation, "database": db_name, "attached_data": json.loads(attached_data), "status": "found "+str(len(result)), "doc(s)": result}
                else:
                    return {"operation": db_operation, "database": db_name, "attached_data": json.loads(attached_data), "status": "no documents found in "+db_name}
            else:
                print('\n*** Invalid operation ('+db_operation+') selected.')
                return {"operation": db_operation, "database": db_name, "attached_data": json.loads(attached_data), "status": "selected operation not found"}
        else: # when database not found
            print('\n*** Invalid database ('+db_name+') selected.')
            return {"operation": db_operation, "database": db_name, "attached_data": json.loads(attached_data), "status": "selected database not found"}   
        # return {"operation": db_operation, "database": db_name, "attached_data": json.loads(attached_data)}

# CVE lookup for given product
class CVEs(Resource): # resource class will handle get and post
    def get(self, attached_data):
        print("Attached data:", attached_data)
        product = attached_data.replace(" ", "+")
        url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="+product
        print('Search string:', product, url)
        df_list = pd.read_html(url)
        
        if (len(df_list)!=5): # len(df_list) # if 5 on MITRE page, then the following code will work.
            print('\n*** Page style changed at MITRE website, reconfigure')

        cves_list = ((df_list[2]['Name']).to_string(index=False).split())
        print('\n*** ' + str(len(cves_list)) + ' vulnerabilities found in '+ attached_data)
        print(cves_list)
        return jsonify({"found_cves": len(cves_list), "product": attached_data, "cve_list": cves_list})

# Describe_CVE
class Describe_CVE(Resource):
    def get(self, attached_data):
        print("Attached data:", attached_data) 
        db_name = 'cyvia_dataset'
        db = server[db_name] # select database      

        print('\n*** Looking for', attached_data)
        doc_found=False
        if attached_data in db: 
            print('Document found!') # print(json.dumps(db[attached_data], indent=4))
            return db[attached_data]
        else:            
            print('Document not found!')
            return jsonify({"message": "CVE "+attached_data+" not found in knowledgebase."})


# Get_CVE_Info
class CVE_info(Resource):
    def get(self, attached_data):
        print("Attached data:", attached_data) 
        db_name = 'cyvia_dataset'
        db = server[db_name] # select database      
        cve_id = attached_data

        full_data_mitre, short_data_mitre, cyvia_data = {}, {}, {}
        found_con, found_mit = False, False
        
        cve_details_url = "https://cveawg.mitre.org/api/cve/"+cve_id
        # get MITRE API results on the CVE
        try:
            response = urlopen(cve_details_url)
            full_data_mitre = json.loads(response.read())        
        except:
            full_data_mitre[cve_id], short_data_mitre[cve_id] = "CVE not found on MITRE", "CVE not found on MITRE"
            
        # find values for these keys from data
        scope_lookup, note_lookup, strategy_lookup, desc_lookup = 'IMPACT', 'NOTE', 'STRATEGY', 'DESCRIPTION'
        
        # print(cve_id)
        # print('Finding information for', '\033[1m'+cve_id+'\033[0m', '...\n')
        if cve_id in db:
            cyvia_data[cve_id] = {}
            
            # MITRE information
            if cve_id not in short_data_mitre:
                # get product version(s)
                prod_vers, prob_types = [], []
                for v in range(0, len(full_data_mitre['containers']['cna']['affected'][0]['versions'])):
                    prod_vers.append(full_data_mitre['containers']['cna']['affected'][0]['versions'][v]['version']) 

                for p in range(0, len(full_data_mitre['containers']['cna']['problemTypes'])):
                    for pd in range(0, len(full_data_mitre['containers']['cna']['problemTypes'][p]['descriptions'])):
                        prob_types.append(full_data_mitre['containers']['cna']['problemTypes'][p]['descriptions'][pd]['description'])
                
                cyvia_data[cve_id]['description'] = full_data_mitre['containers']['cna']['descriptions'][0]['value']
                cyvia_data[cve_id]['vendor'] = full_data_mitre['containers']['cna']['affected'][0]['vendor']
                cyvia_data[cve_id]['affected_product'] = full_data_mitre['containers']['cna']['affected'][0]['product']
                cyvia_data[cve_id]['version(s)'] = prod_vers
                cyvia_data[cve_id]['problem_type(s)'] = prob_types
                
                # Clear 'n/a' fields!
                if cyvia_data[cve_id]['vendor'] == 'n/a': del cyvia_data[cve_id]['vendor']
                if cyvia_data[cve_id]['affected_product'] == 'n/a': del cyvia_data[cve_id]['affected_product']
                if cyvia_data[cve_id]['version(s)'] == ['n/a']: del cyvia_data[cve_id]['version(s)']
                if cyvia_data[cve_id]['problem_type(s)'] == ['n/a']: del cyvia_data[cve_id]['problem_type(s)']

            # Consequences Scope, Impact and notes.
            if db[cve_id]['cwe_consequences'] != {}:
                found_con = True
                x=[]
                for key in db[cve_id ]['cwe_consequences'].keys():
                    x.append(key)                
                cyvia_data[cve_id]['Target(T)'] = [*set(x)]
                # get all impact values for target
                item_impact = [val[scope_lookup] for key, val in db[cve_id]['cwe_consequences'].items() if scope_lookup in val]
                item_impact = [i for sublist in item_impact for i in sublist] # make one list, remove sublists
                cyvia_data[cve_id]['T_Impact(TI)'] = [*set(item_impact)] # remove duplicates
                # Notes
                item_notes = [val[note_lookup] for key, val in db[cve_id]['cwe_consequences'].items() if note_lookup in val]
                item_notes = [i for sublist in item_notes for i in sublist] # make one list, remove sublists
                # if len(item_notes)!=0: cyvia_data[cve_id]['TI_Notes'] = item_desc # [:2] show first 2 only
            
            # Mitigation, prevention, strategies and descriptions.
            if db[cve_id]['cwe_mitigations'] != {}:
                found_mit = True
                x=[]
                for key in db[cve_id]['cwe_mitigations'].keys():
                    x.append(key)
                cyvia_data[cve_id]['Prevent(P)'] = [*set(x)]
                item_strategy = [val[strategy_lookup] for key, val in db[cve_id]['cwe_mitigations'].items() if strategy_lookup in val]
                item_strategy = [i for sublist in item_strategy for i in sublist] # make one list, remove sublists
                if len(item_strategy)!=0: cyvia_data[cve_id]['P_Strategy(PS)'] = [*set(item_strategy)] # remove duplicates [*set(item_strategy)]
                # Descriptions
                item_desc = [val[desc_lookup] for key, val in db[cve_id]['cwe_mitigations'].items() if desc_lookup in val]
                item_desc = [i for sublist in item_desc for i in sublist] # make one list, remove sublists
                if len(item_desc)!=0: cyvia_data[cve_id]['PS_Details'] = item_desc # [:2] show first 2 only
            
            # If nothing found
            if found_con==False and found_mit==False: cyvia_data[cve_id] = "No consequences or mitigation information found"

        else:
            cyvia_data[cve_id] = "CVE not found in CyVIA dataset"

        print(json.dumps(cyvia_data, indent=2))
        return cyvia_data

# Classify Vulnerability Description
class Classify_Desc(Resource):
    def get(self, attached_data):
        attack_type = classify_cve_description(attached_data)
        return jsonify({"description": attached_data, "prediction": attack_type})

# Analyze node(s)
class CyVIA_analysis(Resource):        
    def get(self, attached_data):
        db_name = 'cyvia_nodes' # nodes database 
        db = server[db_name] # select database
        
        total_cves, total_products = [], [] # list of total cves for all apps, and all apps
        product_to_cve = {} # dictionary to keep product to CVE data
        products_not_found, cves_not_found = [], [] # list of products and cves for which no informaiton is found.
        host_name, host_ip, host_os = '','','' # keep node information.

        # attached_doc = json.loads(attached_data) # make json of attached data
        print('Preparing analysis for host', attached_data)

        if (len(db) >= 1): # if documents exist in db then query
            #attached_doc = json.loads(attached_data) # make json of attached data

            if attached_data == 'all_nodes': # analysis for all nodes
                # Time the execution
                now = datetime.now()
                current_time = now.strftime("%H:%M:%S")
                print("Start Time:", current_time)
                startTime = datetime.now() # start timer

                # Extract products from the node document
                node_product_list=[]
                for doc in db:
                    node_product_list.append(doc['HostOS'])
                    if len(doc['applications']) >=1: # if there are products in applications
                        node_product_list.extend(doc['applications']) # add applications to the node_product_list

                # Find CVEs for the found products
                print('\n*** Finding CVE list for products from MITRE ...')

                # Loop through the products to find vulnerabilities
                for product in node_product_list:
                    product = product.replace(" ", "+")
                    url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="+product
                    df_list = pd.read_html(url)
                    if (len(df_list)!=5):
                        print("Page style changed at MITRE website, reconfigure")
                    else: 
                        found_cves = ((df_list[2]['Name']).to_string(index=False).split())
                        if found_cves == ['Series([],', ')']: # if no data is found for product
                            products_not_found.append(product)
                        else: # if CVE list found    
                            if len(found_cves) != 0:
                                product_to_cve[product] = found_cves # product to CVE mapping
                                total_cves.extend(found_cves) # add found CVEs in the total_cves list

                print('Total '+str(len(total_cves))+' CVEs found in '+str(len(node_product_list))+' products where for '+str(len(products_not_found))+' products had no CVEs found on MITRE:\n')
                print(products_not_found)

                # CVE to Product mapping
                cve_to_product = {}
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
                            
                # method to return CVE record from the dataset database
                print('\n*** Finding CVE information from CyVIA dataset ...')
                db_name = 'cyvia_dataset' # change database
                db = server[db_name] # select database
                docs = db.get_bulk(total_cves) # extract all documents with ids (total_cves) # docs[i] returns doc i

                # craft a dataframe (df_all) to hold all data for further processing
                df_all = pd.DataFrame(columns=['_id', 'cwe_id', 'cwe_desc', 'severity', 'cvss_v2'])
                # loop through documents to extract specific information to be added in the dataframe df_all
                for i in range(len(docs)):
                    if (docs[i]!=None):
                        df_all = df_all.append({'_id': docs[i]['_id'], 'cwe_id': docs[i]['cwe_id'], 'cwe_desc': docs[i]['cwe_desc'], 'severity': docs[i]['severity'], 'cvss_v2': docs[i]['cvss_v2']}, ignore_index=True)
                    else:
                        #print(i, total_cves[i], '- No record found, consider updating dataset!')
                        cves_not_found.append(total_cves[i])
                print('Total '+str(len(df_all))+' CVE records found in CyVIA dataset, and '+str(len(cves_not_found))+' not found:\n')
                print(cves_not_found)

                x = json.loads(df_all['severity'].value_counts().to_json())
                y = json.loads(df_all['_id'].value_counts()[:10].to_json())
                z = json.loads(df_all['cwe_id'].value_counts()[:10].to_json())
                print('\nAnalysis as follows {Severity}, {Top10 CVEs}, {Top10 CWEs}')
                print(json.dumps([x, y, z], indent=4))
                print("\nExecution time: "+str(datetime.now() - startTime))
                return ([x, y, z])

            else: # analysis for one node
                # Time the execution
                now = datetime.now()
                current_time = now.strftime("%H:%M:%S")
                print("Start Time:", current_time)
                startTime = datetime.now() # start timer

                # Extract products from the node document
                node_product_list=[]
                # for key, value in attached_doc.items():
                print('\n*** Looking for', attached_data)

                doc_found=False
                for doc in db:
                    try:
                        if doc['HostName']==attached_data: # if document has key level with int value 4
                            doc_found=True
                            print('Document found!') # print(json.dumps(doc, indent=4))
                            host_name, host_ip, host_os = doc['HostName'], doc['HostIP'], doc['HostOS']
                            node_product_list.append(doc['HostOS'])
                            if len(doc['applications']) >=1: # if there are products in applications
                                node_product_list.extend(doc['applications']) # add applications to the node_product_list
                                total_products.extend(doc['applications'])

                    except KeyError: # ignore documents that do not have key
                        pass
                if doc_found==False: print('Document not found!')

                # Find CVEs for the found products
                total_cves = [] # list of total cves for all apps
                product_to_cve = {} # dictionary to keep product to CVE data
                products_not_found, cves_not_found = [], [] # list of products and cves for which no informaiton is found.
                print('\n*** Finding CVE list for products from MITRE ...')

                # Loop through the products to find vulnerabilities
                for product in node_product_list:
                    product = product.replace(" ", "+")
                    url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="+product
                    df_list = pd.read_html(url)
                    if (len(df_list)!=5):
                        print("Page style changed at MITRE website, reconfigure")
                    else: 
                        found_cves = ((df_list[2]['Name']).to_string(index=False).split())
                        if found_cves == ['Series([],', ')']: # if no data is found for product
                            products_not_found.append(product)
                        else: # if CVE list found    
                            if len(found_cves) != 0:
                                product_to_cve[product] = found_cves # product to CVE mapping
                                total_cves.extend(found_cves) # add found CVEs in the total_cves list

                unique_total_cves = [*set(total_cves)] # unique
                
                if len(products_not_found) !=0:
                    print('Total '+str(len(total_cves))+' CVEs found in '+str(len(node_product_list))+' products where for '+str(len(products_not_found))+' products, no CVE information was found on MITRE!\n')
                    print(products_not_found)
                    
                # method to return CVE record from the dataset database
                print('\n*** Finding CVE information from CyVIA dataset ...')
                db_name = 'cyvia_dataset' # change database
                db = server[db_name] # select database
                docs = db.get_bulk(total_cves) # extract all documents with ids (total_cves) # docs[i] returns doc i

                # craft a dataframe (df_all) to hold all data for further processing
                df_all = pd.DataFrame(columns=['_id', 'cwe_id', 'cwe_desc', 'severity', 'cvss_v2'])
                # loop through documents to extract specific information to be added in the dataframe df_all
                for i in range(len(docs)):
                    if (docs[i]!=None):
                        df_all = df_all.append({'_id': docs[i]['_id'], 'description': docs[i]['description'], 'cwe_id': docs[i]['cwe_id'], 'cwe_desc': docs[i]['cwe_desc'], 'severity': docs[i]['severity'], 'cvss_v2': docs[i]['cvss_v2']}, ignore_index=True)
                    else:
                        #print(i, total_cves[i], '- No record found, consider updating dataset!')
                        cves_not_found.append(total_cves[i])
                if len(cves_not_found)!=0:
                    print('\n## Out of '+str(len(df_all))+' CVE records, the following '+str(len(cves_not_found))+' CVEs not found in CyVIA dataset!')
                    print(cves_not_found, '\n')

                x = json.loads(df_all['severity'].value_counts().to_json())
                y = json.loads(df_all['_id'].value_counts()[:10].to_json())
                z = json.loads(df_all['cwe_id'].value_counts()[:10].to_json())
                                
                # find individual cve details from new MITRE source and CyVIA dataset 
                pass_counter, fail_counter, not_in_cyvia, no_con_and_mit, not_on_mitre = 0, 0, 0, 0, 0
                found_cwes, found_attack_types, cwe_to_cve_list, missing_con_list, cve_not_in_cyvia, cve_not_in_mitre = [], [], [], [], [], []
                for cve_id in total_cves: # Testing first few only, remove [:xx]
                    #print('## DEBUG ##')
                    print('Working on', cve_id, end=', ')
                    #print('## END DEBUG ##')
                    
                    # Information fetch from New MITRE Source
                    cyvia_data = get_cve_info(cve_id)
                    
                    # Add unique and information available cve ids for con and mit usage
                    if cve_id not in cwe_to_cve_list:
                        if cyvia_data[cve_id] == "No consequences or mitigation information found": 
                            missing_con_list.append(cve_id)
                            print('Missing consequences and mitigation information!')
                            no_con_and_mit+=1
                            continue
                        #else: cwe_to_cve_list.append(cve_id) # add unique cve_ids with con and mit information available.                     
                        elif cyvia_data[cve_id] == "CVE not found in CyVIA dataset":
                            cve_not_in_cyvia.append(cve_id)
                            print('CVE not found in CyVIA dataset!')
                            not_in_cyvia+=1
                            continue
                        elif cyvia_data[cve_id] == "CVE not found on MITRE!":
                            cve_not_in_mitre.append(cve_id)
                            print('CVE not found on MITRE!\n')
                            not_on_mitre+=1
                            continue
                        else: cwe_to_cve_list.append(cve_id) # add unique cve_ids with con and mit information available.    
                    
                        # Information from CyVIA dataset
                        cwe_id_df = df_all.loc[df_all['_id'] == cve_id]['cwe_id']
                        
                        if cwe_id_df.empty: 
                            # print('\n### CVE not found in CyVIA dataset! ###')
                            # print('Description from MITRE:', cyvia_data[cve_id]['description']) #
                            try:
                                cve_pred = classify_cve_description(cyvia_data[cve_id]['description'])
                                print('\n** CVE:', cve_id, '* CWE Info: N/A', '* CyVIA Pred. Attack Type:', cve_pred, '**\n')
                            except TypeError: 
                                print('CVE to CWE match not found!\n') # cyvia_data[cve_id]['description']
                                # print(json.dumps(cyvia_data, indent=2))
                                continue # go to next cve
                        # else: print(cwe_id_df)
                        
                        cwe_id = df_all.loc[df_all['_id'] == cve_id]['cwe_id'].tolist()[0] # from dataframe, match cve_id and get cwe_id(s), and descriptions in a list. as there are more, take the first
                        cve_desc = df_all.loc[df_all['_id'] == cve_id]['description'].tolist()[0]
                        # print('#### Desc', df_all.loc[df_all['_id'] == cve_id]['description'])
                        
                        if cwe_id == 'NVD-CWE-Other': cwe_desc = 'Other'
                        elif cwe_id == 'NVD-CWE-noinfo': cwe_desc = 'noinfo'
                        else: cwe_desc = df_all.loc[df_all['_id'] == cve_id]['cwe_desc'].tolist()[0]
                        cve_pred = classify_cve_description(cve_desc)
                        
                        # print(df_all.loc[df_all['_id'] == cve_id]['cwe_id'][0])
                        # print(df_all.loc[df_all['_id'] == cve_id].iloc[:1]['cwe_id'])#[0]
                        
                        # CWE types and attack types
                        #print('###', cwe_desc, '***', cve_pred, '###')
                        found_cwes.append(cwe_desc)
                        found_attack_types.append(cve_pred)

                        if 'affected_product' in cyvia_data[cve_id] and cyvia_data[cve_id]['affected_product'].lower() != 'n/a': 
                            # print(cve_id, '\t', cyvia_data[cve_id]['affected_product']) # , '\t', df_all.loc[df_all['_id'] == cve_id]['cwe_id'][1], '\t', df_all.loc[df_all['_id'] == cve_id]['cwe_desc'][1]
                            print('\n** CVE:', cve_id, '* MITRE Attack Type:', cwe_id, '*', cwe_desc, '* \nCyVIA Pred. Attack Type:', cve_pred, '* Affected Product:', cyvia_data[cve_id]['affected_product'], '**\n')
                            pass_counter+=1
                        else: 
                            # print(cve_id, '\t', 'N/A') # , '\t', df_all.loc[df_all['_id'] == cve_id]['cwe_id'][1], '\t', df_all.loc[df_all['_id'] == cve_id]['cwe_desc'][1]
                            print('\n** CVE:', cve_id, '* MITRE Attack Type:', cwe_id, '*', cwe_desc, '* \nCyVIA Pred. Attack Type:', cve_pred, '**\n')
                            fail_counter+=1
                
                # CWEs and Attack types
                pd.set_option('display.max_colwidth', None) # show full column text
                pd.options.display.max_rows
                df_cwes = pd.DataFrame(found_cwes, columns =['CWEs'])
                df_attack_types = pd.DataFrame(found_attack_types, columns =['Attacks'])
                
                # find mitigation information
                # return [*set(vendors)], [*set(affected_products)], [*set(problem_types)], [*set(targets)], [*set(impacts)], [*set(prevents)], [*set(p_strategies)], p_dets_short
                vendors, aff_prods, prob_types, targets, impacts, prevents, p_strat, p_strat_det = find_mitigation(cwe_to_cve_list)
                
                print('\n** Node Analysis')
                print("Host Name:", host_name)
                print("Host IP:", host_ip)
                print("Host OS:", host_os)
                print("Installed Products:", len(total_products))
                print("Found CVEs:", len(total_cves))
                print('\n{Severity}, {Top10 CVEs}, {Top10 CWEs}')
                print(json.dumps([x, y, z], indent=2))
                print("\nExecution time: "+str(datetime.now() - startTime))               
                
                print('Found products:', pass_counter, 'Not found products:', fail_counter, 'Not found in CyVIA Dataset', not_in_cyvia, 'No con and mit found', no_con_and_mit, 'Not found on MITRE', not_on_mitre)
                print(len(cwe_to_cve_list), len([*set(cwe_to_cve_list)])) # [*set(cwe_to_cve_list)]
                
                print('Total MITRE Attack Types:', len(found_cwes), 'Unique:', len([*set(found_cwes)])) # , '\n', [*set(found_cwes)]
                df_cwe_count = df_cwes.groupby(['CWEs'])['CWEs'].size().reset_index(name='Count').sort_values(['Count'], ascending=False) # .size().reset_index(name='counts')
                print(df_cwe_count) 
                cwe_counts = json.loads(df_cwes['CWEs'].value_counts().to_json()) # json.loads(df_all['_id'].value_counts()[:10].to_json()) # top 10

                print('Total CyVIA Attack types:', len(found_attack_types), 'Unique:', len([*set(found_attack_types)])) # , '\n', [*set(found_attack_types)]
                df_attack_count = df_attack_types.groupby(['Attacks'])['Attacks'].size().reset_index(name='Count').sort_values(['Count'], ascending=False)
                print(df_attack_count) 
                attack_types = json.loads(df_attack_types['Attacks'].value_counts().to_json())

                # controls
                
                # dependents vs open ports
                
                # 
                
                # df_all = df_all.append({'_id': docs[i]['_id'], 'description': docs[i]['description'], 'cwe_id': docs[i]['cwe_id'], 'cwe_desc': docs[i]['cwe_desc'], 'severity': docs[i]['severity'], 'cvss_v2': docs[i]['cvss_v2']}, ignore_index=True)                
                # print(json.dumps(cyvia_data, indent=2))
                report_data = {"01. Host Name": host_name, "02. Host IP": host_ip, "03. Host OS": host_os, "04. Installed Products": len(total_products), "05. Found CVEs": len(total_cves), 
                                "06. CVE Severity Report": [x], "07. Top 10 CVEs": [y], "08. Top 10 CWEs":[z], "09. Found "+str(len([*set(found_cwes)]))+" MITRE Attack Types": cwe_counts, 
                                "10. Found "+str(len([*set(found_attack_types)]))+" CyVIA Attack_Types": attack_types, "11. Found "+str(len(vendors))+" Vendors": vendors, 
                                "12. Found "+str(len(aff_prods))+" Affected Products": aff_prods, # "13. Problem Types": prob_types, 
                                "13. Targets": targets, "14. Impacts": impacts, "15. Preventions(P)": prevents, "16. Prevention Strategies(PS)": p_strat, "17. PS Details": p_strat_det
                            }
                return jsonify(report_data) # "products_not_found": products_not_found, "cves_not_found": cves_not_found
        else:
            return jsonify({"message": "no nodes found in database"})


# API resources...
api.add_resource(CyVIA, "/CyVIA")
# api.add_resource(Authenticate, "/Authenticate/<string:attached_data>") # ToDo Later
api.add_resource(CyVIA_functions, "/CyVIA_functions/<string:db_operation>/<string:db_name>/<string:attached_data>")
api.add_resource(CVEs, "/CVEs/<string:attached_data>") # http://129.108.4.53:5000/CVEs/Ubuntu 21
api.add_resource(CyVIA_analysis, "/CyVIA_analysis/<string:attached_data>") # http://129.108.4.53:5000/CyVIA_analysis/Win11
api.add_resource(Describe_CVE, "/Describe_CVE/<string:attached_data>") # http://129.108.4.53:5000/Describe_CVE/CVE-2020-0002 # CVE-2015-0030 # CVE-1999-0001
api.add_resource(CVE_info, "/CVE_info/<string:attached_data>") # http://129.108.4.53:5000/CVE_info/CVE-2020-0002 # 
api.add_resource(Classify_Desc, "/Classify_Desc/<string:attached_data>") # http://129.108.4.53:5000/Classify_Desc/A certain contributed script for ekg Gadu Gadu client 1.5 and earlier allows attackers to execute shell commands via unknown attack vectors.

'''
http://129.108.4.53:5000/                               <-- check if API is running.
http://129.108.4.53:5000/CyVIA                          <-- check if CouchDB is up and running.
http://129.108.4.53:5000/CVEs/Win7                      <-- find cves in OS or products Google Chrome, TunnelBear 4.2.10.0, etc.
http://127.0.0.1:5000/CyVIA_analysis/Win11              <-- existing nodes analysis Win11, Win10, Win7, Ubuntu18, Win2016, Win8, Win2012, Ubuntu20, Raspbian
http://129.108.4.53:5000/Describe_CVE/CVE-2015-0030     <-- pull CVE information from CyVIA knowledgebase
http://129.108.4.53:5000/CVE_info/CVE-2020-0002         <-- get most target, consequences, and mitigation
http://129.108.4.53:5000/Classify_Desc/<vuln. desc>     <-- classify text description of the vulnerability.
ToDo:
OS or Product vulnerabilities report classify like a node report if possible.
http://129.108.4.53:5000/Classify_Desc                      <-- Classify vulnerability description

'''

if __name__ == "__main__":
	app.run(host="0.0.0.0", debug=True)