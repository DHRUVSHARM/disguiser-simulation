import os
import urllib.parse
import json
import requests

def retrieve_test_list(country_code):
    country_code = country_code.lower()
    domain_list = list()
    with open('../materials/alexa_list/alexa.txt', 'r') as alexa_list_file:
        alexa_list = alexa_list_file.read().strip().split()
        domain_list += alexa_list

    with open('../materials/citizenlab_lists/global.csv', 'r') as citizen_global_list_file:
        citizen_global_list_file.readline()
        entries = citizen_global_list_file.read().strip().split('\n')
        urls = list(map(lambda x: x.split(',')[0], entries))
        global_list = list(map(lambda x: urllib.parse.urlsplit(x).netloc, urls))
        global_list = list(filter(lambda x: x.split('.')[-1].isalpha(), global_list))
        domain_list += global_list

    
    if country_code + '.csv' in os.listdir('../materials/citizenlab_lists'):
        with open('../materials/citizenlab_lists/' + country_code + '.csv', 'r') as country_list_file:
            country_list_file.readline()
            entries = country_list_file.read().strip().split('\n')
            urls = list(map(lambda x: x.split(',')[0], entries))
            country_list = list(map(lambda x: urllib.parse.urlsplit(x).netloc, urls))
            country_list = list(filter(lambda x: x.split('.')[-1].isalpha(), country_list))
            domain_list += country_list
    
    domain_list = list(dict.fromkeys(domain_list))
    domain_list.sort()

    return domain_list

def get_country_code(ip):
    url = 'http://ipinfo.io/' + ip + '?token=83423c8f71a017'

    try:
        response = requests.get(url)
        response = json.loads(response.content)
    except:
        response = None

    return response['country']

with open('../results/proxyrack/excluded/excluded_dns_probe.txt') as f:
    dns_excluded_ip = f.read().strip().split()


with open('../results/proxyrack/excluded/excluded_http_probe.txt') as f:
    http_excluded_ip = f.read().strip().split()

with open('../materials/domain_webpage/valid_domains.txt') as f:
    valid_domains = f.read().strip().split()
valid_domain_dic = dict()
for domain in valid_domains:
    valid_domain_dic[domain] = True

dns_requests = 0
http_requests = 0

for ip in dns_excluded_ip:
    country_code = get_country_code(ip)
    domain_list = retrieve_test_list(country_code)
    for domain in domain_list:
        if domain in valid_domain_dic:
            dns_requests += 1

for ip in http_excluded_ip:
    country_code = get_country_code(ip)
    domain_list = retrieve_test_list(country_code)
    for domain in domain_list:
        if domain in valid_domain_dic:
            http_requests += 1

print('dns_requests:', dns_requests)
print('http_requests:', http_requests)