import json
import dns.resolver
import requests
import tqdm
from bs4 import BeautifulSoup
import sys


correct_http_page = 'http\n'
correct_http_contact = 'linjin@udel.edu'

result_path = '../results/proxyrack/'
start_date = sys.argv[1]
suffix = 'http_proxyrack_censorship_json.txt'

with open('../results/proxyrack/excluded/excluded_http_probe.txt') as f:
    http_excluded_ip = f.read().strip().split()
with open('../results/proxyrack/excluded/excluded_http_probe_manual.txt') as f:
    http_excluded_ip_manual = f.read().strip().split()
    
with open('../materials/domain_webpage/valid_domains.txt') as f:
    valid_domains = f.read().strip().split()
valid_domain_dic = dict()
for domain in valid_domains:
    valid_domain_dic[domain] = True


def get_suspicious_vps():
    censorship_filename = result_path + start_date + '/' + start_date + '_' + suffix
    processed_ip_list = list()

    suspicious_vps = dict() 
    with open(censorship_filename, 'r') as censorship_file:
        for entry in censorship_file:
            entry_dic = json.loads(entry.strip())
            proxy = entry_dic['proxy']
            if proxy['query'] not in processed_ip_list and proxy['query'] not in http_excluded_ip and proxy['query'] not in http_excluded_ip_manual:
                processed_ip_list.append(proxy['query'])
                ip = proxy['query']
                domain_dic = entry_dic['domain']
                country = proxy['country']

                for domain in domain_dic.keys():
                    if not valid_domain_dic.get(domain, False):
                        continue
                    test_result = domain_dic[domain][-1]
                    if test_result['text'] != correct_http_page and test_result['text'] != '' and correct_http_contact not in test_result['text']:
                        if ip not in suspicious_vps.keys():
                            suspicious_vps[ip] = dict()
                            suspicious_vps[ip]['country'] = country
                            suspicious_vps[ip]['domain'] = dict()
                        if domain not in suspicious_vps[ip]['domain'].keys():
                            suspicious_vps[ip]['domain'][domain] = dict()
                        suspicious_vps[ip]['domain'][domain]['text'] = test_result['text']
                        suspicious_vps[ip]['domain'][domain]['headers'] = test_result['headers']
                              
    return suspicious_vps


def webpage_heuristics():
    webpage_confirmed_vps = list()
    for vp in suspicious_vps:
        domains = suspicious_vps[vp]['domain'].keys()
        for domain in domains:
            try:
                vp_response = suspicious_vps[vp]['domain'][domain]['text']
                vp_title = BeautifulSoup(vp_response, "html.parser").title.string
                local_title = webpage_title_dic[domain]
                
                if vp_title == local_title and local_title != '':
                    webpage_confirmed_vps.append(vp)
                    break
            except:
                pass

    return webpage_confirmed_vps


webpage_title_dic = dict()
with open('../materials/domain_webpage/domain_title_dict_2021.txt') as f:
    for entry in f:
        entry_dic = json.loads(entry.strip())
        domain = list(entry_dic.keys())[0]
        title = entry_dic[domain]
        webpage_title_dic[domain] = title




print(start_date)
suspicious_vps = get_suspicious_vps()
print(len(suspicious_vps))

webpage_confirmed_vps = webpage_heuristics()

for vp in webpage_confirmed_vps:
    suspicious_vps.pop(vp)

print(len(suspicious_vps))



with open('../results/proxyrack/' + start_date + '/http_manual_case.txt', 'w') as f:
    f.write(json.dumps(suspicious_vps))

with open('../results/proxyrack/excluded/excluded_http_probe.txt', 'a') as f:
    for vp in webpage_confirmed_vps:
        f.write(vp + '\n')





######################################################################## temp
# header_count = dict()
# suspicious_vps = get_suspicious_vps()
# for vp in suspicious_vps:
#     domains = suspicious_vps[vp].keys()
#     for domain in domains:
#         headers = suspicious_vps[vp][domain]['headers']
#         for header in headers:

#             header_count[header] = header_count.get(header, 0) + 1

# for header in header_count:
#     print(header_count[header], header)