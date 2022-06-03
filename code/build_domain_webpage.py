import requests
import urllib
import os
from bs4 import BeautifulSoup
import joblib
import tqdm
import datetime
import sys
import json

def retrieve_domain_list():
    domain_list = list()
    with open('../materials/alexa_list/alexa.txt', 'r') as alexa_list_file:
        alexa_list = alexa_list_file.read().strip().split()
        domain_list += alexa_list
    
    for country_file in os.listdir('../materials/citizenlab_lists'):
        if not country_file.startswith('0') and os.path.isfile('../materials/citizenlab_lists/' + country_file):
            with open('../materials/citizenlab_lists/' + country_file, 'r') as country_list_file:
                country_list_file.readline()
                entries = country_list_file.read().strip().split('\n')
                urls = list(map(lambda x: x.split(',')[0], entries))
                country_list = list(map(lambda x: urllib.parse.urlsplit(x).netloc, urls))
                country_list = list(filter(lambda x: x.split('.')[-1].isalpha(), country_list))
                domain_list += country_list
    
    domain_list = list(dict.fromkeys(domain_list))
    domain_list.sort()

    return domain_list



def get_domain_webpage(domain):
    url = 'http://' + domain
    headers = dict()
    headers['User-Agent'] = 'Mozilla/5.0'
    try:
        webpage = requests.get(url, headers = headers, timeout = 5).text
    except:
        webpage = ''

    return domain, webpage


domain_list = retrieve_domain_list()

step = 100
for i in range(int(len(domain_list) / step) + 1):
    begin = i * step
    end = min(begin + step, len(domain_list))
    print(datetime.datetime.now().time(), '\t', 'Start analyzing websites', begin + 1, '~', end)
    results = joblib.Parallel(n_jobs = -1,  backend="threading") (joblib.delayed(get_domain_webpage) (domain) for domain in domain_list[begin:end])

    for result in results:
        domain, webpage = result
        json_string = json.dumps({domain: webpage})
        with open('../materials/domain_webpage/domain_webpage_dict_2021.txt', 'a+') as f:
            f.write(json_string + '\n')
        
        try:
            title = BeautifulSoup(webpage, "html.parser").title.string
        except:
            title = ''
        json_string = json.dumps({domain: title})
        with open('../materials/domain_webpage/domain_title_dict_2021.txt', 'a+') as f:
            f.write(json_string + '\n')


