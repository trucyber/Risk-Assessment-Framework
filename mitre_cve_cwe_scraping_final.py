# CWE Scrapping
import pandas as pd
import multiprocessing as mp

# Based on the provided search string, related CVEs will be scraped using MITRE CVE results
# CWE types for each CVE will be scraped
# parent and children CWEs for the found CWEs will be scraped
# search_string = "Windows Server 2008 build 6002"
product_list = ['Windows Server 2008 build 6002', 'Windows Server 2008 build 6002', 'Windows Server 2008 build 6002', 
                'Windows Server 2008 build 6002', 'Microsoft System Center build 5.0.8412.1309', 
                'Microsoft Windows 8.1 Pro 6.3.9600 N/A Build 9600', 'Microsoft Windows 8.1 Pro 6.3.9600 N/A Build 9600',
                'Microsoft Windows 8.1 Pro 6.3.9600 N/A Build 9600', 'Microsoft Windows 8.1 Pro 6.3.9600 N/A Build 9600',
                'Microsoft Windows 7 Professional 6.1.7601 Service Pack 1 Build 7601', 'Microsoft Windows 7 Professional 6.1.7601 Service Pack 1 Build 7601',
                'Microsoft Windows 7 Professional 6.1.7601 Service Pack 1 Build 7601',
                'FortiGate 2.8', 'FortiGate 2.8', 'Alpine Linux 3.10', 'Alpine Linux 3.10',
                'Cisco NX-OS 5.2', 'Cisco NX-OS 5.2', 'Cisco NX-OS 5.2', 'Cisco NX-OS 5.2', 'Cisco NX-OS 5.2',
                'Zoneminder 1.30', 'Aware Security', 'Wordpress 5.3', 'Epson PowerLite', 'HP LaserJet 8000dn', 'Canon imageRUNNER 1643i',
                'Kaspersky Security 10.1.1', 'Kaspersky Security 10.1.1', 'Kaspersky Security 10.1.1', 'Kaspersky Security 10.1.1','Kaspersky Security 10.1.1',
                'Kaspersky Security 10.1.1', 'Kaspersky Security 10.1.1', 'Kaspersky Security 10.1.1', 'Kaspersky Security 10.1.1','Kaspersky Security 10.1.1',
                'Acrobat Reader 10.0', 'Acrobat Reader 10.0', 'Acrobat Reader 10.0', 'Acrobat Reader 10.0', 'Acrobat Reader 10.0',
                'Microsoft Office 2017', 'Microsoft Office 2017', 'Microsoft Office 2017', 'Microsoft Office 2017', 'Microsoft Office 2017', 
                'WinRAR 5.91', 'WinRAR 5.91', 'WinRAR 5.91', 'WinRAR 5.91', 'WinRAR 5.91'
               ]
			   
p_list = list(set(product_list)) # Unique list, removing duplicates from the product_list to avoid reduncency 
len(p_list)

def find_cves(product):
    # Get CVEs using pandas from the CVE page results using a search String
    product = product.replace(" ", "+")
    url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="+product
    print('Search string:', product, url)
    # url = 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=Windows+10'
    df_list = pd.read_html(url)
    # len(df_list) # if 5, then the following code will work.

    if (len(df_list)!=5):
        print("Page style changed at MITRE website, reconfigure")
    # else:
        #     print(df_list[2])    

    # print ((df_list[2]['Name']).to_string(index=False))
    cves_list = ((df_list[2]['Name']).to_string(index=False).split())
    print('Total vulns found:', len(cves_list))
#     print(*cves_list, sep=', ') 
    return cves_list
	
product_to_cve = {}
for p in p_list:
    product_to_cve[p] = find_cves(p)

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
	
# a container for all CVE entries.
total_cves = []

# for search_string in p_list:
for search_string in product_list:
    total_cves.extend(find_cves(search_string))

print('\nTotal CVEs count:', len(total_cves))
# print(*total_cves, sep=', ')

summary_file = 'vulns_info_v31.csv'
# cwe_reference = 'cwe_ref.csv'

df_summary = pd.read_csv(summary_file, encoding = 'UTF-8')
df_summary = df_summary[~df_summary.CVE_ID.isna()]

df_summary['product'] = df_summary.CVE_ID.apply(lambda x: cve_to_product.get(x, None))
df_summary = df_summary.dropna(subset=['product'])
df_summary['product'] = df_summary['product'].apply(lambda x: x[0])

# Read CVE count from excel for duplicating rows for re-occurring vulnerabilities.
data_df = pd.read_excel("Risk Model v3.xlsx", sheet_name="Sheet1", skiprows=2, usecols=[1, 2], names=['product_name', 'CVE'])
data_df = data_df.dropna()

# ToDo: Fix this product issue, it is not showing in data, not matching with summary
data_df[data_df.product_name.apply(lambda x: x not in p_list)]

def duplicate(row):
    product_name = row['product_name']
    cve_count = row['CVE']
    cve_list = product_to_cve.get(product_name, None)
    if cve_list is None: return None
    output = df_summary[df_summary["CVE_ID"].isin(cve_list)]
    return output
	
temp = data_df.apply(lambda x: duplicate(x), axis=1) # list of dataframes for each row in data_df
temp_clean = [t for t in temp if t is not None]

final_data_df = pd.concat(temp_clean, ignore_index=True)

print(final_data_df['Severity'].value_counts())
final_data_df['Severity'].value_counts().plot(kind='bar');

# Product-wise CWE count 
y = final_data_df.groupby(["product", "CWE_ID"]).size().reset_index(name="Counts")

# df_final = final_data_df.groupby(["CWE_ID"]).size().reset_index(name="Counts").sort_values('Counts', ascending=False)
df_final = final_data_df['CWE_ID'].value_counts().rename_axis('CWE_ID').reset_index(name='Count')
# df_final

# Load CWE-Data from CWE_MASTER 
cwe_master = 'cwe_master1.csv'

import pandas
df_cwe = pandas.read_csv(cwe_master, engine='python')
# df_cwe.loc[df_cwe['CWE-ID'] == df_res.loc[1, "CWE_ID"]]
names, parents = [], []

# iterate through the list
for i in range(len(df_final)) : 
    n = (df_cwe.loc[df_cwe['CWE_ID'] == df_final.loc[i, "CWE_ID"]][['Name']].to_string(index=False)).strip()
    names.append(n[6:].strip()) # Because .strip('Name\n') was stripping N from the NULL Pointer Dereference.
    p = (df_cwe.loc[df_cwe['CWE_ID'] == df_final.loc[i, "CWE_ID"]][['Parents']].to_string(index=False)).strip()
    p = p[9:].strip()
    if (p=='[]'):# if parent is []
        parents.append('None')
    else:
#         parents.append(p[9:].strip())
        p = ''.join(c for c in p if c not in '[]\'')
        parents.append(p)

# Calculating % of risk.
percen = []
for i in range(len(df_final)):
    p = (df_final['Count'][i] * 100) / df_final['Count'].sum()
    percen.append(round(p, 2))
    
# add Names column to dataframe df_final
df_final['Names'] = names
# add parents column to dataframe df_final
df_final['Parents'] = parents
# add the percent column to dataframe df_final
df_final['%'] = percen

# df_final.to_csv('df_final.csv')

print('Total CVEs present in products:', len(total_cves))
print('Total CVEs matched with summary file for detail extraction:', len(final_data_df))
print('Difference:', len(total_cves) - len(final_data_df))
print('Total categories generated:', len(df_final))
print('Sum count:', df_final['Count'].sum())

# df_final

df_final.head(10)

# Top 10 categories
final_data_df['CWE_ID'].value_counts()[:10].plot(kind='bar')

# CWE-wise product counts 
x = final_data_df.groupby(["CWE_ID", "product"]).size().reset_index(name="Counts")
# pandas.set_option('display.max_rows', x.shape[0]+1)
x


