import json
import os
import sys

proxy_path = '../results/proxyrack/'
subdirs = [ f.path for f in os.scandir(proxy_path) if f.is_dir() ]
subdirs.sort()

def dns_vp_fraction():
    country_dic = dict()
    for subdir in subdirs:
        if subdir.split('/')[-1].startswith('20'):
            date = subdir.split('/')[-1]
            with open(subdir + '/' + date + '_dns_final.txt') as f:
                for entry in f:
                    if entry != '\n':
                        entry_dic = json.loads(entry)
                        country = entry_dic['country']
                        if country not in country_dic:
                            country_dic[country] = dict()
                            country_dic[country]['country'] = country
                            country_dic[country]['total_vps'] = set()
                            country_dic[country]['censored_vp'] = set()

                        country_dic[country]['total_vps'] = country_dic[country]['total_vps'].union(entry_dic['ip'])
                        for domain in entry_dic['domain']:
                            country_dic[country]['censored_vp'] = country_dic[country]['censored_vp'].union(set(entry_dic['domain'][domain]['ip']))

    for country in country_dic:
        country_dic[country]['total_vps'] = list(country_dic[country]['total_vps'])
        country_dic[country]['censored_vp'] = list(country_dic[country]['censored_vp'])
        country_dic[country]['fraction'] = len(country_dic[country]['censored_vp']) / len(country_dic[country]['total_vps'])

    return country_dic



def http_vp_fraction():
    country_dic = dict()
    for subdir in subdirs:
        if subdir.split('/')[-1].startswith('20'):
            date = subdir.split('/')[-1]
            with open(subdir + '/' + date + '_http_final.txt') as f:
                for entry in f:
                    if entry != '\n':
                        entry_dic = json.loads(entry)
                        country = entry_dic['country']
                        if country not in country_dic:
                            country_dic[country] = dict()
                            country_dic[country]['country'] = country
                            country_dic[country]['total_vps'] = set()
                            country_dic[country]['censored_vp'] = set()

                        country_dic[country]['total_vps'] = country_dic[country]['total_vps'].union(entry_dic['ip'])
                        for domain in entry_dic['domain']:
                            country_dic[country]['censored_vp'] = country_dic[country]['censored_vp'].union(set(entry_dic['domain'][domain]['ip']))

    for country in country_dic:
        country_dic[country]['total_vps'] = list(country_dic[country]['total_vps'])
        country_dic[country]['censored_vp'] = list(country_dic[country]['censored_vp'])
        country_dic[country]['fraction'] = len(country_dic[country]['censored_vp']) / len(country_dic[country]['total_vps'])

    return country_dic



def sni_vp_fraction():
    country_dic = dict()
    for subdir in subdirs:
        if subdir.split('/')[-1].startswith('20'):
            date = subdir.split('/')[-1]
            with open(subdir + '/' + date + '_sni_final.txt') as f:
                for entry in f:
                    if entry != '\n':
                        entry_dic = json.loads(entry)
                        country = entry_dic['country']
                        if country not in country_dic:
                            country_dic[country] = dict()
                            country_dic[country]['country'] = country
                            country_dic[country]['total_vps'] = set()
                            country_dic[country]['censored_vp'] = set()

                        country_dic[country]['total_vps'] = country_dic[country]['total_vps'].union(entry_dic['ip'])
                        for domain in entry_dic['domain']:
                            country_dic[country]['censored_vp'] = country_dic[country]['censored_vp'].union(set(entry_dic['domain'][domain]['ip']))

    for country in country_dic:
        country_dic[country]['total_vps'] = list(country_dic[country]['total_vps'])
        country_dic[country]['censored_vp'] = list(country_dic[country]['censored_vp'])
        country_dic[country]['fraction'] = len(country_dic[country]['censored_vp']) / len(country_dic[country]['total_vps'])

    return country_dic


country_dic = dns_vp_fraction()
with open('../results/proxyrack/final/dns_vp_fraction.txt', 'w') as f:
    for country in country_dic:
        f.write(json.dumps(country_dic[country]) + '\n\n')


country_dic = http_vp_fraction()
with open('../results/proxyrack/final/http_vp_fraction.txt', 'w') as f:
    for country in country_dic:
        f.write(json.dumps(country_dic[country]) + '\n\n')


country_dic = sni_vp_fraction()
with open('../results/proxyrack/final/sni_vp_fraction.txt', 'w') as f:
    for country in country_dic:
        f.write(json.dumps(country_dic[country]) + '\n\n')