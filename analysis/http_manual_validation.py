import json
import os
import sys     
import webbrowser
import random
import hashlib
from bs4 import BeautifulSoup

proxy_path = '../results/proxyrack/'
subdirs = [ f.path for f in os.scandir(proxy_path) if f.is_dir() ]
subdirs.sort()

def get_webpages():
    webpage_dic = dict()
    unique_webpage = set()
    for subdir in subdirs:
        if subdir.split('/')[-1].startswith('20'):
            start_date = subdir.split('/')[-1]
            with open(subdir + '/' + 'http_manual_case.txt') as f:
                vps = json.loads(f.read().strip())
                for vp in vps:
                    country = vps[vp]['country']
                    for domain in vps[vp]['domain']:
                        webpage = vps[vp]['domain'][domain]['text']
                        headers = vps[vp]['domain'][domain]['headers']
                        soup = BeautifulSoup(webpage, 'html.parser')
                        document = soup.find_all()
                        tags = [x.name for x in document]
                        tags_string = ' '.join(tags)
                        webpage_hash = hashlib.md5(tags_string.encode()).hexdigest()
                        #webpage_hash = hashlib.md5(webpage.encode()).hexdigest()
                        
                        unique_webpage.add(webpage)
                        if webpage_hash not in webpage_dic.keys():
                            webpage_dic[webpage_hash] = list()
                        
                        entry = tuple((start_date, country, vp, domain, webpage, headers))
                        webpage_dic[webpage_hash].append(entry)
    return webpage_dic, unique_webpage

webpage_dic, unique_webpage = get_webpages()
print(len(webpage_dic.keys()))
for webpage_hash in sorted(webpage_dic, key = lambda x: len(webpage_dic[x]), reverse = True):
    print(webpage_hash, len(webpage_dic[webpage_hash]))

print('unique_webpage:', len(unique_webpage))

count = 0
for webpage_hash in sorted(webpage_dic, key = lambda x: len(webpage_dic[x]), reverse = True):
    count += 1
    if webpage_hash != '4c3f3c11dfa6110db724d1c715f549f2':
        continue
    print(webpage_hash, len(webpage_dic[webpage_hash]), count, '/', len(webpage_dic.keys()))
    webpage_info_list = webpage_dic[webpage_hash]
    random.shuffle(webpage_info_list)

    for index, webpage_info in enumerate(webpage_info_list[:20]):
        start_date, country, vp, domain, webpage, headers = webpage_info
        path = os.path.abspath('temp/temp' + str(index) + '.html') 
        url = 'file://' + path
        with open(path, 'w') as f: 
            f.write(domain + '\n' + webpage_hash + '\n' + webpage)
        webbrowser.open(url)
        print(start_date, country, vp, len(webpage), domain)
        print(headers)
        print()
    input("Press Enter to continue...")