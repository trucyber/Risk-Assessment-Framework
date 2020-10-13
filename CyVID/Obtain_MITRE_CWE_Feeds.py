# CWE CSV Handler...

# Imports
import os, glob, requests, re, zipfile, timeit
from os import listdir
from os.path import isfile, join

# global variables...
cwe_files_path = 'mitre_csv_files' # CSV files path globally
sw_dev_url = 'https://cwe.mitre.org/data/csv/699.csv.zip'
hw_design_url = 'https://cwe.mitre.org/data/csv/1194.csv.zip'
research_concepts_url =  'https://cwe.mitre.org/data/csv/1000.csv.zip'

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
        print('Creating directory', dir_path, 'to store feeds.', end=' ')
        directory = os.path.join(os.getcwd()+'\\' + dir_path) 
        os.mkdir(directory)
        print('Done.\n')

# 2. Download files...
def download_csv_files(feed_url):
    # Start obtaining new feeds...
    print('Obtaining MITRE CVS',os.path.basename(feed_url),'feed from: '+feed_url+'...', end=' ')
    r = requests.get(feed_url) # where the files are...
    r_file = requests.get(feed_url, stream=True)
    with open(cwe_files_path + '/' + os.path.basename(feed_url), 'wb') as f: # path, file name from URL
        for chunk in r_file.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
        print('Done.')

# 3. Unzip and Delete zip files...
# Extract the files from the downloaded zip files from the previous step, and remove the zip files.
def extract_and_remove_zips(file_path):
    print('\nPreparing files.')
    files = [f for f in listdir(file_path + '/' ) if isfile(join(file_path, f))]
    files.sort()
    for file in files:
        archive = zipfile.ZipFile(join(file_path + '/' , file), 'r')
        print('Extracting ' + join(file_path + '/' , file) + '... ', end='')
        archive.extractall(os.getcwd()+'\\'+file_path) # add here
        archive.close()
        print('Done. ', end='')
        # remove zip files after extraction
        if file.endswith('.zip'):
            print('Removing zip file' + '... ', end='')
            try:
                os.remove(join(file_path + '/' , file))
                print('Done.')
            except PermissionError:
                print('Error removing file:', join(file_path + '/' , file))    

# 4. Merge CSV file data
def merge_csv_files(file_path):
    import pandas as pd 
    directory = os.path.join(os.getcwd()+'\\'+cwe_files_path+'\\') 
    sw_list = pd.read_csv(directory+'699.csv', engine='python', encoding='ISO-8859-1', index_col=False)
    hw_list = pd.read_csv(directory+'1000.csv', engine='python', encoding='ISO-8859-1', index_col=False)
    res_con = pd.read_csv(directory+'1194.csv', engine='python', encoding='ISO-8859-1', index_col=False)
    frames = [sw_list, hw_list, res_con]
    combined_list = pd.concat(frames)
    combined_list = res.sort_values(by = 'CWE-ID')
    combined_list.to_csv(directory+'Combined_CWE.csv', index=False)
    print("\nFiles combined into one file, Combined_CWE.csv")
    
print('*** MITRE CWE Handler v3 ***\n')

# time the execution
start = timeit.default_timer() # start timer

# Step 1
check_files(cwe_files_path)

# Step 2
download_csv_files(sw_dev_url)
download_csv_files(hw_design_url)
download_csv_files(research_concepts_url)

# Step 3
extract_and_remove_zips(cwe_files_path)

# Step 4
merge_csv_files(cwe_files_path)

stop = timeit.default_timer()
execution_time = stop - start
print("\nMITRE CWE Feeds obtained.")
print("Execution time: "+str(execution_time)) # It returns time in seconds
