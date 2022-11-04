import json
import dns.resolver
import requests
from bs4 import BeautifulSoup
import pyasn
import sys

correct_ip_list = ["100.100.100.100"]


def get_rcode_reason(rcode):
    if rcode == -1:
        return 'NORESPONSE'
    elif rcode == 0:
        return 'NOERROR'
    elif rcode == 2:
        return 'SERVFAIL'
    elif rcode == 3:
        return 'NXDOMAIN'
    elif rcode == 5:
        return 'REFUSED'
    else:
        return 'RCODE = ' + str(rcode)



def extract_ip_address(dns_response):
    ip_list = list()
    for rr in dns_response.rrset:
        ip_list.append(rr.address)
    return ip_list


def retrieve_webpage(url, headers):
    response = requests.get(url, allow_redirects=False, headers = headers, timeout = 5)
    if int(response.status_code / 100) == 3:
        headers.pop('Host')
        response = requests.get(response.headers['location'], headers = headers, timeout = 5)
    return response



def get_suspicious_vps():
    censorship_filename = result_path + start_date + '/' + start_date + '_' + suffix
    processed_ip_list = list()

    suspicious_vps = dict() 
    with open(censorship_filename, 'r') as censorship_file:
        for entry in censorship_file:
            entry_dic = json.loads(entry.strip())
            proxy = entry_dic['proxy']
            if proxy['query'] not in processed_ip_list and proxy['query'] not in dns_excluded_ip:
                processed_ip_list.append(proxy['query'])
                ip = proxy['query']
                domain_dic = entry_dic['domain']

                for domain in domain_dic.keys():
                    if not valid_domain_dic.get(domain, False):
                        continue
                    test_result = domain_dic[domain][-1]
                    if test_result['ip_list'] != correct_ip_list and test_result['rcode'] == 0:
                        if ip not in suspicious_vps.keys():
                            suspicious_vps[ip] = dict()
                            suspicious_vps[ip][domain] = test_result['ip_list']
                        else:
                            suspicious_vps[ip][domain] = test_result['ip_list']
                              
    return suspicious_vps



def get_ripe_atlas_suspicious_vps():
    censorship_filename = '../results/ripe_atlas/ripe_atlas_results_updated.txt'
    suspicious_vps = dict() 
    with open(censorship_filename, 'r') as censorship_file:
        for entry in censorship_file:
            entry_dic = json.loads(entry.strip())
            if entry_dic['error'] != '' and 'socket' in entry_dic['error'].keys():
                continue
            proxy = entry_dic['probe']
            ip = proxy['query']
            domain = entry_dic['domain']
            if proxy['query'] in ripe_atlas_excluded_ip:
                continue
            if entry_dic['ip_list'] != correct_ip_list and entry_dic['rcode'] == 0:
                if ip not in suspicious_vps.keys():
                    suspicious_vps[ip] = dict()
                    suspicious_vps[ip][domain] = entry_dic['ip_list']
                else:
                    suspicious_vps[ip][domain] = entry_dic['ip_list']
    return suspicious_vps



def dns_resolution_heuristics():
    dns_confirmed_vps = list()
    for vp in suspicious_vps.keys():
        vp_confirmed = False
        domains = suspicious_vps[vp].keys()
        for domain in domains:
            try:
                dns_response = dns.resolver.query(domain)
                ip_list = extract_ip_address(dns_response)
            except:
                ip_list = []
                pass

            
            #asn_list = list(map(lambda x: asndb.lookup(x)[0], ip_list))

            for ip in suspicious_vps[vp][domain]:
                if ip in ip_list: # or asndb.lookup(ip)[0] in asn_list:
                    vp_confirmed = True
                    dns_confirmed_vps.append(vp)
                    break
            
            if vp_confirmed:
                break
    return dns_confirmed_vps


def webpage_heuristics(dns_confirmed_vps):
    http_confirmed_vps = list()
    for vp in suspicious_vps:
        if vp in dns_confirmed_vps:
            continue
        vp_confirmed = False
        domains = suspicious_vps[vp].keys()
        for domain in domains:
            for ip in suspicious_vps[vp][domain]:
                headers = dict()
                headers['Host'] = domain
                headers['User-Agent'] = 'Mozilla/5.0'

                vp_url = 'http://' + ip
                local_url = 'http://' + domain
                
                try:
                    vp_response = retrieve_webpage(vp_url, headers = headers).text
                    vp_title = BeautifulSoup(vp_response, "html.parser").title.string
                    local_response = requests.get(local_url, timeout = 5).text
                    local_title = BeautifulSoup(local_response, "html.parser").title.string
                    

                    if vp_title == local_title:
                        vp_confirmed = True
                        http_confirmed_vps.append(vp)
                        break
                except:
                    pass
            if vp_confirmed:
                    break
    return http_confirmed_vps



result_path = '../results/proxyrack/'
start_date = sys.argv[1]
suffix = 'dns_proxyrack_censorship_json.txt'

asndb = pyasn.pyasn('../materials/as_database/ipasn_20200526.dat')


with open('../results/proxyrack/excluded/excluded_dns_probe.txt') as f:
    dns_excluded_ip = f.read().strip().split()

with open('../materials/domain_webpage/valid_domains.txt') as f:
    valid_domains = f.read().strip().split()
valid_domain_dic = dict()
for domain in valid_domains:
    valid_domain_dic[domain] = True


################################################# Proxyrack DNS ##########################################
suspicious_vps = get_suspicious_vps()

dns_confirmed_vps = dns_resolution_heuristics()


http_confirmed_vps = webpage_heuristics(dns_confirmed_vps)
confirmed_vps = dns_confirmed_vps + http_confirmed_vps

for vp in confirmed_vps:
    suspicious_vps.pop(vp)


with open('../results/proxyrack/' + start_date + '/dns_manual_case.txt', 'w') as f:
    f.write(json.dumps(suspicious_vps))

with open('../results/proxyrack/excluded/excluded_dns_probe.txt', 'a') as f:
    for vp in confirmed_vps:
        f.write(vp + '\n')
################################################# Proxyrack DNS ##########################################



################################################# China DNS ##########################################
# with open('../results/ripe_atlas/china_results.txt') as f:
#     for entry in f:
#         domain = entry.split()[0]
#         ip = entry.split('\'')[1]
#         if ip != '100.100.100.100':
#             headers = dict()
#             headers['Host'] = domain
#             headers['User-Agent'] = 'Mozilla/5.0'
#             vp_url = 'http://' + ip
#             try:
#                 vp_response = retrieve_webpage(vp_url, headers = headers).text
#             except:
#                 vp_response = ''
#             output_dic = {'domain': domain, 'ip': ip, 'webpage': vp_response}
#             with open('../results/ripe_atlas/china_manual_webpage.txt', 'a+') as output:
#                 output.write(json.dumps(output_dic) + '\n')
            



################################################# China DNS ##########################################




################################################# Ripe Atlas DNS ##########################################
# with open('../results/ripe_atlas/exclude.txt') as f:
#     ripe_atlas_excluded_ip = f.read().strip().split()

# suspicious_vps = get_ripe_atlas_suspicious_vps()

# print(suspicious_vps)

################################################# Ripe Atlas DNS ##########################################