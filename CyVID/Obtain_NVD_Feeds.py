# NVD JSON Handler...

# Imports
import os, glob, requests, re, zipfile, timeit
from os import listdir
from os.path import isfile, join

# global variables...
json_files_path = 'nvd_json_files' # JSON files path globally
json_feed_url = 'https://nvd.nist.gov/vuln/data-feeds#JSON_FEED'

# 1. Download files...
def download_json_files(feed_url):
    # Check if the directory for json files exists, if not create one.
    if (os.path.isdir(os.getcwd()+'\\'+json_files_path)): # if folder does not exist, create one
        print('Directory',json_files_path,'already exists.')
        # remove old files from the directory
        print('Removing old files...')
        files = glob.glob(os.getcwd()+'\\'+json_files_path+'\\*')
        for f in files:
            os.remove(f)    
    else:
        print('Creating directory',json_files_path, 'to store JSON feeds.')
        current_path = os.getcwd()
        directory = os.path.join(current_path+'\\', json_files_path) 
        os.mkdir(directory)

    # Start obtaining new feeds...
    print('\nObtaining JSON feeds from NVD...\n['+json_feed_url+']')
    r = requests.get(feed_url) # where the files are...
    for filename in re.findall('nvdcve-1.1-[0-9]*\.json\.zip', r.text): # yearly file names e.g. nvdcve-1.1-2020.json.zip 
        print('File ' + filename +' found. ', end='')
        r_file = requests.get('https://nvd.nist.gov/feeds/json/cve/1.1/' + filename, stream=True)
        with open(json_files_path + '/' + filename, 'wb') as f:
            print('Downloading... ', end='')
            for chunk in r_file.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
            print('done.')

# 2. Unzip and Delete zip files...
# Extract the JSON files from the downloaded zip files from the previous step, and remove the zip files.
def extract_and_remove_json():
    print('\nExtracting JSON files.')
    files = [f for f in listdir(json_files_path + '/' ) if isfile(join(json_files_path, f))]
    files.sort()
    for file in files:
        archive = zipfile.ZipFile(join(json_files_path + '/' , file), 'r')
        print('Extracting ' + join(json_files_path + '/' , file) + '... ', end='')
        archive.extractall(os.getcwd()+'\\'+json_files_path) # add here
        archive.close()
        print('done. ', end='')
        # remove zip files after extraction
        if file.endswith('.zip'):
            print('Removing zip file' + '... ', end='')
            try:
                os.remove(join(json_files_path + '/' , file))
                print('done.')
            except PermissionError:
                print('Error removing file:', join(json_files_path + '/' , file))    
    
print('*** NVD JSON Handler v3 ***\n')

# time the execution
start = timeit.default_timer() # start timer

# Step 1
download_json_files(json_feed_url)

# Step 2
extract_and_remove_json()

stop = timeit.default_timer()
execution_time = stop - start
print("\nNVD Feeds obtained.")
print("Execution time: "+str(execution_time)) # It returns time in seconds