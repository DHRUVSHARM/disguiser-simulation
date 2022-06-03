import json
import os
import sys


proxy_path = '../results/proxyrack/'
subdirs = [ f.path for f in os.scandir(proxy_path) if f.is_dir() ]
subdirs.sort()


def dns_statistic():
    country_dic = dict()
    for subdir in subdirs:
        if subdir.split('/')[-1].startswith('2021'):
            date = subdir.split('/')[-1]
            with open(subdir + '/' + date + '_dns_final.txt') as f:
                for entry in f:
                    if entry != '\n':
                        entry_dic = json.loads(entry)
                        country = entry_dic['country']
                        if country not in country_dic:
                            country_dic[country] = dict()
                            country_dic[country]['country'] = country
                            country_dic[country]['total_domains'] = entry_dic['total_domains']
                            country_dic[country]['domain'] = list()
                            country_dic[country]['category'] = list()
                            country_dic[country]['rcode_reason'] = list()
                            country_dic[country]['is_timeout'] = list()
                            country_dic[country]['total_requests'] = 0

                        country_dic[country]['total_requests'] += entry_dic['total_domains'] * len(entry_dic['ip'])

                        for domain in entry_dic['domain']:
                            if domain not in country_dic[country]['domain']:
                                country_dic[country]['domain'].append(domain)
                                country_dic[country]['category'].append(entry_dic['domain'][domain]['category'])
                            country_dic[country]['rcode_reason'] += entry_dic['domain'][domain]['rcode_reason']
                            if 'is_timeout' in entry_dic['domain'][domain].keys():
                                country_dic[country]['is_timeout'] += entry_dic['domain'][domain]['is_timeout']

    for country in country_dic:
        country_dic[country]['count'] = len( country_dic[country]['domain'])
        country_dic[country]['percentage'] = country_dic[country]['count'] / country_dic[country]['total_domains']
    
    return country_dic




def http_statistic():
    country_dic = dict()
    for subdir in subdirs:
        if subdir.split('/')[-1].startswith('2021'):
            date = subdir.split('/')[-1]
            with open(subdir + '/' + date + '_http_final.txt') as f:
                for entry in f:
                    if entry != '\n':
                        entry_dic = json.loads(entry)
                        country = entry_dic['country']
                        if country not in country_dic:
                            country_dic[country] = dict()
                            country_dic[country]['country'] = country
                            country_dic[country]['total_domains'] = entry_dic['total_domains']
                            country_dic[country]['domain'] = list()
                            country_dic[country]['category'] = list()
                            country_dic[country]['text'] = list()
                            country_dic[country]['is_timeout'] = list()
                            country_dic[country]['total_requests'] = 0
                        
                        country_dic[country]['total_requests'] += entry_dic['total_domains'] * len(entry_dic['ip'])

                        for domain in entry_dic['domain']:
                            if domain not in country_dic[country]['domain']:
                                country_dic[country]['domain'].append(domain)
                                country_dic[country]['category'].append(entry_dic['domain'][domain]['category'])
                            
                            country_dic[country]['text'] += entry_dic['domain'][domain]['text']
                            if 'is_timeout' in entry_dic['domain'][domain].keys():
                                country_dic[country]['is_timeout'] += entry_dic['domain'][domain]['is_timeout']

    for country in country_dic:
        country_dic[country]['count'] = len( country_dic[country]['domain'])
        country_dic[country]['percentage'] = country_dic[country]['count'] / country_dic[country]['total_domains']

    return country_dic


def sni_statistic():
    country_dic = dict()
    for subdir in subdirs:
        if subdir.split('/')[-1].startswith('2021'):
            date = subdir.split('/')[-1]
            with open(subdir + '/' + date + '_sni_final.txt') as f:
                for entry in f:
                    if entry != '\n':
                        entry_dic = json.loads(entry)
                        country = entry_dic['country']
                        if country not in country_dic:
                            country_dic[country] = dict()
                            country_dic[country]['country'] = country
                            country_dic[country]['total_domains'] = entry_dic['total_domains']
                            country_dic[country]['domain'] = list()
                            country_dic[country]['category'] = list()
                            country_dic[country]['cert_serial'] = list()
                            country_dic[country]['is_timeout'] = list()
                            country_dic[country]['total_requests'] = 0
                        
                        country_dic[country]['total_requests'] += entry_dic['total_domains'] * len(entry_dic['ip'])
                        for domain in entry_dic['domain']:
                            if domain not in country_dic[country]['domain']:
                                country_dic[country]['domain'].append(domain)
                                country_dic[country]['category'].append(entry_dic['domain'][domain]['category'])
                            
                            country_dic[country]['cert_serial'] += entry_dic['domain'][domain]['cert_serial']
                            if 'is_timeout' in entry_dic['domain'][domain].keys():
                                country_dic[country]['is_timeout'] += entry_dic['domain'][domain]['is_timeout']

    for country in country_dic:
        country_dic[country]['count'] = len( country_dic[country]['domain'])
        country_dic[country]['percentage'] = country_dic[country]['count'] / country_dic[country]['total_domains']

    return country_dic



def overall_statistic():
    country_dic = dict()
    with open('../results/proxyrack/final/2021_dns_overall.txt', 'r') as f:
        for entry in f:
            if entry != '\n':
                entry_dic = json.loads(entry)
                country = entry_dic['country']
                if country not in country_dic:
                    country_dic[country] = dict()
                    country_dic[country]['country'] = country
                    country_dic[country]['total_domains'] = entry_dic['total_domains']
                    country_dic[country]['domain'] = list()
                    country_dic[country]['category'] = list()
                for domain in entry_dic['domain']:
                    if domain not in country_dic[country]['domain']:
                        country_dic[country]['domain'].append(domain)
                    category = domain_category_dic[domain]
                    if category not in country_dic[country]['category']:
                        country_dic[country]['category'].append(category)

    with open('../results/proxyrack/final/2021_http_overall.txt', 'r') as f:
        for entry in f:
            if entry != '\n':
                entry_dic = json.loads(entry)
                country = entry_dic['country']
                if country not in country_dic:
                    country_dic[country] = dict()
                    country_dic[country]['country'] = country
                    country_dic[country]['total_domains'] = entry_dic['total_domains']
                    country_dic[country]['domain'] = list()
                    country_dic[country]['category'] = list()
                for domain in entry_dic['domain']:
                    if domain not in country_dic[country]['domain']:
                        country_dic[country]['domain'].append(domain)
                    category = domain_category_dic[domain]
                    if category not in country_dic[country]['category']:
                        country_dic[country]['category'].append(category)

    with open('../results/proxyrack/final/2021_sni_overall.txt', 'r') as f:
        for entry in f:
            if entry != '\n':
                entry_dic = json.loads(entry)
                country = entry_dic['country']
                if country not in country_dic:
                    country_dic[country] = dict()
                    country_dic[country]['country'] = country
                    country_dic[country]['total_domains'] = entry_dic['total_domains']
                    country_dic[country]['domain'] = list()
                    country_dic[country]['category'] = list()
                for domain in entry_dic['domain']:
                    if domain not in country_dic[country]['domain']:
                        country_dic[country]['domain'].append(domain)
                    category = domain_category_dic[domain]
                    if category not in country_dic[country]['category']:
                        country_dic[country]['category'].append(category)

    for country in country_dic:
        country_dic[country]['count'] = len( country_dic[country]['domain'])
        country_dic[country]['percentage'] = country_dic[country]['count'] / country_dic[country]['total_domains']
    
    return country_dic



def policy_consistency():
    country_dic = dict()
    with open('../results/proxyrack/final/dns_overall.txt', 'r') as f:
        for entry in f:
            if entry != '\n':
                entry_dic = json.loads(entry)
                country = entry_dic['country']
                if country not in country_dic:
                    country_dic[country] = dict()
                    country_dic[country]['country'] = country
                    country_dic[country]['total_domains'] = entry_dic['total_domains']
                    country_dic[country]['dns_domain'] = list()
                    country_dic[country]['http_domain'] = list()
                    country_dic[country]['https_domain'] = list()
                for domain in entry_dic['domain']:
                    if domain not in country_dic[country]['dns_domain']:
                        country_dic[country]['dns_domain'].append(domain)
    
    with open('../results/proxyrack/final/http_overall.txt', 'r') as f:
        for entry in f:
            if entry != '\n':
                entry_dic = json.loads(entry)
                country = entry_dic['country']
                if country not in country_dic:
                    country_dic[country] = dict()
                    country_dic[country]['country'] = country
                    country_dic[country]['total_domains'] = entry_dic['total_domains']
                    country_dic[country]['dns_domain'] = list()
                    country_dic[country]['http_domain'] = list()
                    country_dic[country]['https_domain'] = list()
                for domain in entry_dic['domain']:
                    if domain not in country_dic[country]['http_domain']:
                        country_dic[country]['http_domain'].append(domain)


    with open('../results/proxyrack/final/sni_overall.txt', 'r') as f:
        for entry in f:
            if entry != '\n':
                entry_dic = json.loads(entry)
                country = entry_dic['country']
                if country not in country_dic:
                    country_dic[country] = dict()
                    country_dic[country]['country'] = country
                    country_dic[country]['total_domains'] = entry_dic['total_domains']
                    country_dic[country]['dns_domain'] = list()
                    country_dic[country]['http_domain'] = list()
                    country_dic[country]['https_domain'] = list()
                for domain in entry_dic['domain']:
                    if domain not in country_dic[country]['https_domain']:
                        country_dic[country]['https_domain'].append(domain)
    
    country_list = list()
    for country in country_dic:
        dns_domain = country_dic[country]['dns_domain']
        http_domain = country_dic[country]['http_domain']
        https_domain = country_dic[country]['https_domain']

        if len(set(dns_domain) | set(http_domain) | set(https_domain)) / country_dic[country]['total_domains'] < 0.05:
            country_list.append(country)
            continue

        try:
            dns_http_similarity = len(set(dns_domain) & set(http_domain)) / len(set(dns_domain) | set(http_domain))
        except ZeroDivisionError:
            dns_http_similarity = 0
        try:
            dns_https_similarity = len(set(dns_domain) & set(https_domain)) / len(set(dns_domain) | set(https_domain))
        except ZeroDivisionError:
            dns_https_similarity = 0
        try:
            http_https_similarity = len(set(http_domain) & set(https_domain)) / len(set(http_domain) | set(https_domain))
        except ZeroDivisionError:
            http_https_similarity = 0
        try:
            dns_http_https_similarity = len(set(dns_domain) & set(http_domain) & set(https_domain)) / len(set(dns_domain) | set(http_domain) | set(https_domain))
        except ZeroDivisionError:
            dns_http_https_similarity = 0
        
        country_dic[country]['dns_http_similarity'] = dns_http_similarity
        country_dic[country]['dns_https_similarity'] = dns_https_similarity
        country_dic[country]['http_https_similarity'] = http_https_similarity
        country_dic[country]['dns_http_https_similarity'] = dns_http_https_similarity

    # for country in country_list:
    #     country_dic.pop(country)
    

    return country_dic



domain_category_dic = dict()
with open('../materials/domain_category/domain_category_dict.txt') as f:
    for entry in f:
        components = entry.strip().split()
        domain = components[0]
        category = ' '.join(components[1:])
        domain_category_dic[domain] = category


country_dic = dns_statistic()
with open('../results/proxyrack/final/2021_dns_overall.txt', 'w') as f:
    for country in country_dic:
        f.write(json.dumps(country_dic[country]) + '\n\n')
                        
country_dic = http_statistic()
with open('../results/proxyrack/final/2021_http_overall.txt', 'w') as f:
    for country in country_dic:
        f.write(json.dumps(country_dic[country]) + '\n\n')

country_dic = sni_statistic()
with open('../results/proxyrack/final/2021_sni_overall.txt', 'w') as f:
    for country in country_dic:
        f.write(json.dumps(country_dic[country]) + '\n\n')


country_dic = overall_statistic()
with open('../results/proxyrack/final/2021_overall_statistic.txt', 'w') as f:
    for country in country_dic:
        f.write(json.dumps(country_dic[country]) + '\n\n')


# country_dic = policy_consistency()
# with open('../results/proxyrack/final/policy_consistency.txt', 'w') as f:
#     for country in country_dic:
#         f.write(json.dumps(country_dic[country]) + '\n\n')

# dns = 0
# http = 0
# https = 0
# dns_http = 0
# dns_https = 0
# http_https = 0
# dns_http_https = 0

# for country in country_dic:
#     value = 0
#     if len(country_dic[country]['dns_domain']) != 0:
#         value += 1
#     if len(country_dic[country]['http_domain']) != 0:
#         value += 2
#     if len(country_dic[country]['https_domain']) != 0:
#         value += 4
#     if value == 1:
#         dns += 1
#         print(country)
#     if value == 2:
#         http += 1
#     if value == 3:
#         dns_http += 1
#     if value == 4:
#         https += 1
#     if value == 5:
#         dns_https += 1
#     if value == 6:
#         http_https += 1
#     if value == 7:
#         dns_http_https += 1

# print('dns:', dns)
# print('http:', http)
# print('https:', https)
# print('dns_http', dns_http)
# print('dns_https', dns_https)
# print('http_https', http_https)
# print('dns_http_https', dns_http_https)
