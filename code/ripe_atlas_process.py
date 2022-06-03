import json
import sys

correct_ip_list = ["100.100.100.100"]
correct_http_page = 'http\n'
correct_cert_serial = ['85723161702102284164881707705813409552803205256', '201614099203817838842043426670715639081255164964']
dns_threshold = 0
http_threshold = 5

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


result_path = '../results/ripe_atlas/ripe_atlas_results_updated.txt'
additional_result_path = '../results/ripe_atlas/ripe_atlas_results_additional_updated.txt'
exclude_filename = '../results/ripe_atlas/exclude.txt'

with open(exclude_filename, 'r') as exclude_file:
    exclude_ip = exclude_file.read().strip().split()




def process_dns():
    censorship_filename = result_path

    result_dic = dict()
    total_count = 0
    with open(censorship_filename, 'r') as censorship_file:
        for entry in censorship_file:
            
            entry_dic = json.loads(entry.strip())
            if 'timeout' in entry:
                with open(additional_result_path, 'r') as addition_results:
                    for additional_entry in addition_results:
                        additional_entry_dic = json.loads(additional_entry.strip())
                        if entry_dic['domain'] == additional_entry_dic['domain'] and entry_dic['probe']['countryCode'] == additional_entry_dic['probe']['countryCode']:
                            entry_dic = additional_entry_dic
            
            if entry_dic['error'] != '' and 'socket' in entry_dic['error'].keys():
                continue
            
            proxy = entry_dic['probe']
            country = proxy['country']
            ip = proxy['query']
            asn = proxy['as'].split()[0]

            if proxy['query'] in exclude_ip:
                continue
            if country == 'United States':
                continue

            total_count += 1
            if country not in result_dic.keys():
                result_dic[country] = dict()
                result_dic[country]['country'] = country
                result_dic[country]['ip'] = list()
                result_dic[country]['asn'] = list()
                result_dic[country]['domain'] = dict()
                result_dic[country]['count'] = 0
            
            if ip not in result_dic[country]['ip']:
                result_dic[country]['ip'].append(ip)
            if asn not in result_dic[country]['asn']:
                result_dic[country]['asn'].append(asn)

            if entry_dic['ip_list'] != correct_ip_list:
                domain = entry_dic['domain']



                if domain not in result_dic[country]['domain']:
                    result_dic[country]['domain'][domain] = dict()
                    result_dic[country]['domain'][domain]['rcode_reason'] = [entry_dic['rcode']]
                    result_dic[country]['domain'][domain]['category'] = domain_category_dic[domain]
                    result_dic[country]['count'] += 1
                    result_dic[country]['domain'][domain]['ip_list'] = entry_dic['ip_list']
                    result_dic[country]['domain'][domain]['ip'] = [ip]
                    result_dic[country]['domain'][domain]['error'] = [entry_dic['error']]
                else:
                    result_dic[country]['domain'][domain]['rcode_reason'].append(entry_dic['rcode'])
                    result_dic[country]['domain'][domain]['ip_list'] += entry_dic['ip_list']
                    result_dic[country]['domain'][domain]['ip'].append(ip)
                    result_dic[country]['domain'][domain]['error'].append(entry_dic['error'])

    return result_dic, total_count


domain_category_dic = dict()
with open('../materials/domain_category/domain_category_dict.txt') as f:
    for entry in f:
        components = entry.strip().split()
        domain = components[0]
        category = ' '.join(components[1:])
        domain_category_dic[domain] = category


result_dic, total_count = process_dns()

with open('../results/ripe_atlas/final.txt', 'w') as f:
    for country in result_dic.keys():
        json_string = json.dumps(result_dic[country])
        f.write(json_string + '\n\n')

print(total_count)
