import requests
import urllib
import os
from bs4 import BeautifulSoup
import tqdm


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


def get_domain_category(domain):
    
    api = 'https://fortiguard.com/webfilter'
    url = api + '?q=' + domain + '&version=8'
    headers = dict()
    headers['User-Agent'] = 'Mozilla/5.0'
    http_response = requests.get(url, headers = headers).text

    soup = BeautifulSoup(http_response, 'html.parser')
    tag = soup.find_all('h4', class_='info_title')[0].contents
    category = tag[0].split(':')[1].strip()

    return category


domain_list = retrieve_domain_list()
with open('../materials/domain_category/domain_category_dict.txt', 'r') as f:
    entries = f.read().strip().split('\n')
    exist_domain = list(map(lambda x: x.split()[0], entries))

domain_list = list(filter(lambda x: x not in exist_domain, domain_list))


for domain in tqdm.tqdm(domain_list):
    category = get_domain_category(domain)
    with open('../materials/domain_category/domain_category_dict.txt', 'a+') as f:
        f.write('%-40s' % domain + '\t' + category + '\n')
