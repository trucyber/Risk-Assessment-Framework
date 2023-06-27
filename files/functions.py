# This file has global functions used across the whole system...
# imports
import os, glob, couchdb2, json, requests, re, zipfile, timeit, time, csv
from csv import DictReader
from time import time as timer
from os import listdir
from os.path import isfile, join

import config # credentials file (user, pass, host, port)

class functions():
    
    # Function to check if the directory exists, if not, create one and remove old files inside.
    def check_files(self, dir_path):
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
            print('Creating directory', dir_path, 'to store feeds.', end=' ')
            directory = os.path.join(os.getcwd()+'\\' + dir_path) 
            os.mkdir(directory)
            print('Done.\n')

    # Function to Unzip zip files and Delete zip files...
    def extract_and_remove_zips(self, file_path):
        print('\nExtracting files...', end=' ')
        files = [f for f in listdir(file_path + '/' ) if isfile(join(file_path, f))]
        files.sort()
        for file in files:
            archive = zipfile.ZipFile(join(file_path + '/' , file), 'r')
            archive.extractall(os.getcwd()+'\\'+file_path) # add here
            archive.close()
            # remove zip files after extraction
            if file.endswith('.zip'):
                try:
                    os.remove(join(file_path + '/' , file))
                except PermissionError:
                    print('Error removing file:', join(file_path + '/' , file))
        print('Done.')
    
    # Make connection to a CouchDB database and select the database for transactions
    def connect_db(self, db_name, erase_db): # database name, if existing data is to be removed first.
        server = couchdb2.Server("http://%s:%s@%s:%s" % (config.db_user, config.db_pass, config.db_host, config.db_port))

        if server.up(): # if server is up and ready
            print('Server status: ('+str(server.version)+') up and running!')               
            if db_name in server: # already existing database # if db.exists():
                if erase_db:
                    functions.db = server[db_name]
                    functions.db.destroy() # deletes all records
                    server.create(db_name)
                    functions.db = server[db_name]
                else:
                    print('Database '+db_name+' found, selecting...')
                    functions.db = server[db_name]
                    print('Database selected:', str(functions.db))
            else: # create database if does not exist
                print('Database '+db_name+' does not exist, creating...')
                server.create(db_name)
                functions.db = server[db_name]
                print('Database selected:', str(functions.db))
        else: # exit if server not running
            print('Server not responding, exiting program!')
            sys.exit()
    
    # Convert seconds to hours minutes and seconds
    def convert_seconds(self, seconds): 
        seconds = seconds % (24 * 3600) 
        hour = seconds // 3600
        seconds %= 3600
        minutes = seconds // 60
        seconds %= 60
        return "%d:%02d:%02d" % (hour, minutes, seconds)

    # Sample function for testing
    def print_me(self, text): 
        functions.a = 1
        functions.b = 2        
        print(text)
        
    # CSV to JSON to CouchDB # Test this function if it is working properly!
    def csv_to_json_to_db(self, csvFilePath, jsonFilePath, db_name, erase_db): # Pass file paths, db name and it to erase old data   
        # Read CSV
        with open(csvFilePath, encoding="utf8") as fd:
            reader = csv.reader(fd, delimiter=",")
            fieldnames = next(reader)
            # print('Field names:', fieldnames)
            data = list(DictReader(fd, fieldnames)) # dump the remaining rows

        # Write JSON
        with open(jsonFilePath, 'w') as fd:
          json.dump(data, fd)

        # Opening JSON and Load data 
        with open(jsonFilePath) as j_data: 
            json_data = json.load(j_data)
        
        # insert to db
        functions.connect_db(self, db_name, erase_db) # function

        # docs = [{'key': 'value1'}, {'key': 'value2'}]
        try:
            for (success, doc_id, revision_or_exception) in functions.db.update(json_data):
                print(success, docid, revision_or_exception)
        except NameError:
            print("End of file.")
