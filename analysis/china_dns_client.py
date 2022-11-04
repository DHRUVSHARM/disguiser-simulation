import dns.query
import dns.message
import dns.name
import dns.rdatatype
import base64
import time
import urllib.parse
import os
import sys
import random
import datetime
import tqdm
import json
import dns.resolver




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





def extract_ip_address(dns_answer):
    ip_list = list()
    for answer in dns_answer:
        ip_list.append(answer.address)
    return ip_list


china_list = retrieve_test_list('CN')
my_resolver = dns.resolver.Resolver()
my_resolver.nameservers = ['52.206.233.21']


for domain in tqdm.tqdm(china_list):
    response = my_resolver.query(domain)
    ip_list = extract_ip_address(response)
    with open('china_results.txt', 'a+') as f:
        f.write(domain + ' '  +str(ip_list) + '\n')




