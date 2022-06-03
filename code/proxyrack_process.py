import json
import sys
import datetime

correct_ip_list = ["100.100.100.100"]
correct_http_page = 'http\n'
correct_http_contact = 'linjin@udel.edu'
correct_cert_serial = ['85723161702102284164881707705813409552803205256', '201614099203817838842043426670715639081255164964']


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




def process_dns():
    censorship_filename = result_path + start_date + '/' + start_date + '_' + 'dns' + suffix

    result_dic = dict()
    processed_ip_list = list()
    with open(censorship_filename, 'r') as censorship_file:
        for entry in censorship_file:
            entry_dic = json.loads(entry.strip())
            proxy = entry_dic['proxy']
            if proxy['query'] not in processed_ip_list and proxy['query'] not in dns_excluded_ip:
                processed_ip_list.append(proxy['query'])
                country = proxy['country']
                ip = proxy['query']
                asn = proxy['as'].split()[0]
                if country not in result_dic.keys():
                    result_dic[country] = dict()
                    result_dic[country]['country'] = country
                    result_dic[country]['ip'] = list()
                    result_dic[country]['asn'] = list()
                    result_dic[country]['domain'] = dict()
                    result_dic[country]['count'] = 0
                    result_dic[country]['total_domains'] = 0
                    for domain in entry_dic['domain'].keys():
                        if valid_domain_dic.get(domain, False):
                            result_dic[country]['total_domains'] += 1
                
                result_dic[country]['ip'].append(ip)
                result_dic[country]['asn'].append(asn)

                domain_dic = entry_dic['domain']

                for domain in domain_dic.keys():
                    if not valid_domain_dic.get(domain, False):
                        continue

                    test_result = domain_dic[domain][-1]
                    if test_result['ip_list'] != correct_ip_list:
                        
                        rcode_reason = get_rcode_reason(test_result['rcode'])
                        if domain not in result_dic[country]['domain']:
                            result_dic[country]['domain'][domain] = dict()
                            result_dic[country]['domain'][domain]['category'] = domain_category_dic[domain]
                            result_dic[country]['count'] += 1
                            result_dic[country]['domain'][domain]['rcode_reason'] = [rcode_reason]
                            result_dic[country]['domain'][domain]['ip_list'] = test_result['ip_list']
                            result_dic[country]['domain'][domain]['ip'] = [ip]
                            if 'is_timeout' in test_result.keys():
                                result_dic[country]['domain'][domain]['is_timeout'] = [test_result['is_timeout']]
                        else:
                            result_dic[country]['domain'][domain]['rcode_reason'].append(rcode_reason)
                            result_dic[country]['domain'][domain]['ip_list'] += test_result['ip_list']
                            result_dic[country]['domain'][domain]['ip'].append(ip)
                            if 'is_timeout' in test_result.keys():
                                result_dic[country]['domain'][domain]['is_timeout'].append(test_result['is_timeout'])
    
    for country in result_dic:
        result_dic[country]['percentage'] = result_dic[country]['count'] / result_dic[country]['total_domains']
    return result_dic




def process_http():
    censorship_filename = result_path + start_date + '/' + start_date + '_' + 'http' + suffix

    result_dic = dict()
    processed_ip_list = list()

    with open(censorship_filename, 'r') as censorship_file:
        for entry in censorship_file:
            entry_dic = json.loads(entry.strip())
            proxy = entry_dic['proxy']
            if proxy['query'] not in processed_ip_list and proxy['query'] not in http_excluded_ip and proxy['query'] not in http_excluded_ip_manual:
                processed_ip_list.append(proxy['query'])
                country = proxy['country']
                ip = proxy['query']
                asn = proxy['as'].split()[0]
                if country not in result_dic.keys():
                    result_dic[country] = dict()
                    result_dic[country]['country'] = country
                    result_dic[country]['ip'] = list()
                    result_dic[country]['asn'] = list()
                    result_dic[country]['domain'] = dict()
                    result_dic[country]['count'] = 0
                    result_dic[country]['total_domains'] = 0
                    for domain in entry_dic['domain'].keys():
                        if valid_domain_dic.get(domain, False):
                            result_dic[country]['total_domains'] += 1
                
                result_dic[country]['ip'].append(ip)
                result_dic[country]['asn'].append(asn)
                
                domain_dic = entry_dic['domain']
                
                for domain in domain_dic.keys():
                    if not valid_domain_dic.get(domain, False):
                        continue
                    test_result = domain_dic[domain][-1]
                    if test_result['text'] != correct_http_page and correct_http_contact not in test_result['text']:
                        if domain not in result_dic[country]['domain']:
                            result_dic[country]['domain'][domain] = dict()
                            result_dic[country]['domain'][domain]['category'] = domain_category_dic[domain]
                            result_dic[country]['count'] += 1
                            # result_dic[country]['domain'][domain]['status_code'] = test_result['status_code']
                            # result_dic[country]['domain'][domain]['url'] = test_result['url']
                            result_dic[country]['domain'][domain]['text'] = [len(test_result['text'])]
                            result_dic[country]['domain'][domain]['ip'] = [ip]
                            if 'is_timeout' in test_result.keys():
                                result_dic[country]['domain'][domain]['is_timeout'] = [test_result['is_timeout']]
                        else:
                            result_dic[country]['domain'][domain]['text'].append(len(test_result['text']))
                            result_dic[country]['domain'][domain]['ip'].append(ip)
                            if 'is_timeout' in test_result.keys():
                                result_dic[country]['domain'][domain]['is_timeout'].append(test_result['is_timeout'])
    for country in result_dic:
        result_dic[country]['percentage'] = result_dic[country]['count'] / result_dic[country]['total_domains']
        
    return result_dic



def process_sni():
    censorship_filename = result_path + start_date + '/' + start_date + '_' + 'sni' + suffix

    result_dic = dict()
    processed_ip_list = list()

    with open(censorship_filename, 'r') as censorship_file:
        for entry in censorship_file:
            entry_dic = json.loads(entry.strip())
            proxy = entry_dic['proxy']
            if proxy['query'] not in processed_ip_list:
                processed_ip_list.append(proxy['query'])
                country = proxy['country']
                ip = proxy['query']
                asn = proxy['as'].split()[0]
                if country not in result_dic.keys():
                    result_dic[country] = dict()
                    result_dic[country]['country'] = country
                    result_dic[country]['ip'] = list()
                    result_dic[country]['asn'] = list()
                    result_dic[country]['domain'] = dict()
                    result_dic[country]['count'] = 0
                    result_dic[country]['total_domains'] = 0
                    for domain in entry_dic['domain'].keys():
                        if valid_domain_dic.get(domain, False):
                            result_dic[country]['total_domains'] += 1
                
                result_dic[country]['ip'].append(ip)
                result_dic[country]['asn'].append(asn)
                
                domain_dic = entry_dic['domain']
                for domain in domain_dic.keys():
                    if not valid_domain_dic.get(domain, False):
                        continue
                    test_result = domain_dic[domain][-1]
                    if test_result['cert_serial'] not in correct_cert_serial:
                        if domain not in result_dic[country]['domain']:
                            result_dic[country]['domain'][domain] = dict()
                            result_dic[country]['domain'][domain]['category'] = domain_category_dic[domain]
                            result_dic[country]['count'] += 1
                            # result_dic[country]['domain'][domain]['status_code'] = test_result['status_code']
                            # result_dic[country]['domain'][domain]['url'] = test_result['url']
                            result_dic[country]['domain'][domain]['cert_serial'] = [test_result['cert_serial']]
                            result_dic[country]['domain'][domain]['ip'] = [ip]
                            if 'is_timeout' in test_result.keys():
                                result_dic[country]['domain'][domain]['is_timeout'] = [test_result['is_timeout']]
                        else:
                            result_dic[country]['domain'][domain]['cert_serial'].append(test_result['cert_serial'])
                            result_dic[country]['domain'][domain]['ip'].append(ip)
                            if 'is_timeout' in test_result.keys():
                                result_dic[country]['domain'][domain]['is_timeout'].append(test_result['is_timeout'])
    for country in result_dic:
        result_dic[country]['percentage'] = result_dic[country]['count'] / result_dic[country]['total_domains']

    return result_dic




domain_category_dic = dict()
with open('../materials/domain_category/domain_category_dict.txt') as f:
    for entry in f:
        components = entry.strip().split()
        domain = components[0]
        category = ' '.join(components[1:])
        domain_category_dic[domain] = category

with open('../results/proxyrack/excluded/excluded_dns_probe.txt') as f:
    dns_excluded_ip = f.read().strip().split()


with open('../results/proxyrack/excluded/excluded_http_probe.txt') as f:
    http_excluded_ip = f.read().strip().split()

with open('../results/proxyrack/excluded/excluded_http_probe_manual.txt') as f:
    http_excluded_ip_manual = f.read().strip().split()


result_path = '../results/proxyrack/'
start_date = sys.argv[2]
suffix = '_proxyrack_censorship_json.txt'


with open('../materials/domain_webpage/valid_domains.txt') as f:
    valid_domains = f.read().strip().split()
valid_domain_dic = dict()
for domain in valid_domains:
    valid_domain_dic[domain] = True


protocol = sys.argv[1]


if protocol == 'dns':
    result_dic = process_dns()
if protocol == 'http':
    result_dic = process_http()
if protocol == 'sni':
    result_dic = process_sni()

with open(result_path + start_date + '/' + start_date + '_' + protocol + '_final.txt', 'w') as f:
    for country in result_dic.keys():
        json_string = json.dumps(result_dic[country])
        f.write(json_string + '\n\n')

