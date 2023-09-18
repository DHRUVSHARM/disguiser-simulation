from ripe.atlas.cousteau import Dns
from ripe.atlas.cousteau import AtlasSource
from ripe.atlas.cousteau import AtlasCreateRequest
from ripe.atlas.cousteau import AtlasLatestRequest
import dns.query
import dns.message
import dns.name
import dns.rdatatype
import base64
import time
import urllib
import os
import sys
import random
import datetime
import tqdm
import json

ATLAS_API_KEY = ''

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


def schedule_dns_measurement(dns_server, target_domain, protocol, country_code_list):
    dns = Dns(
        af = 4, 
        target = dns_server,
        query_class = 'IN',
        query_type = 'A',
        query_argument = target_domain,
        description = 'DNS test ' + dns_server,
        protocol = protocol,
        retry = 5,
        is_public = False
    )

    source_list = list()
    for country_code in country_code_list:
        source = AtlasSource(
            type = 'country',
            value = country_code,
            requested = 1
        )
        source_list.append(source)

    atlas_request = AtlasCreateRequest(
        key = ATLAS_API_KEY,
        measurements =[dns],
        sources = source_list,
        is_oneoff = True
    )

    is_success, response = atlas_request.create()
    if is_success:
        measuremment_id = response['measurements'][0]
    else:
        measuremment_id = 0
        print('Error: ', response)
    return is_success, measuremment_id


def retrieve_measurement_result(measurement_id):
    kwargs = {
        "msm_id": measurement_id
    }

    is_success, results = AtlasLatestRequest(**kwargs).create()
    return is_success, results


def extract_ip_address(dns_response):
    ip_list = list()
    for rrset in dns_response.answer:
        if rrset.rdtype == dns.rdatatype.A:
            for rr in rrset:
                ip_list.append(rr.address)
    return ip_list


def process_raw_dns_response(abuf):
    dns_response = dns.message.from_wire(base64.b64decode(abuf))
    rcode = dns_response.rcode()
    ip_list = list()
    if rcode == 0:
        ip_list = extract_ip_address(dns_response)
    return rcode, ip_list





###################################################################### schedule Iran measurements ############################################################
china_list = retrieve_test_list('CN')
finished_domain_list = []
dns_server1 = '52.206.233.21'
dns_server2 = '128.4.12.93'


# result_path = '../results/ripe_atlas/ripe_atlas_results_iran.txt'
protocol = 'UDP'
log_file = '../results/ripe_atlas/china_additional_measurement.txt'


# with open(log_file, 'r') as f:
#     raw_file = f.read()
#     if raw_file != '':
#         finished_domain_list = raw_file.strip().split('\n')
#         finished_domain_list = list(map(lambda x: x.split()[2], finished_domain_list))
#     else:
#         finished_domain_list = list()

target_domain_list = list(filter(lambda x: x not in finished_domain_list, china_list))

count = 0
for domain in tqdm.tqdm(target_domain_list):

    count += 1
    if count % 2 == 0:
        dns_server = dns_server1
    else:
        dns_server = dns_server2
    
    target_domain = domain
    is_success, measuremment_id = schedule_dns_measurement(dns_server, target_domain, protocol, ['CN'])
    if is_success:
        entry = str(datetime.datetime.now()) + '\t' + target_domain + ' \t' + str(measuremment_id) + '\n'
        with open(log_file, 'a+') as f:
            f.write(entry)
        time.sleep(12)
    else:
        sys.exit(0)
###################################################################### schedule Iran measurements ############################################################








###################################################################### schedule measurements additional ############################################################
# useless_country_list = ["MG", "MN", "US"]
# result_path = '../results/ripe_atlas/ripe_atlas_results_updated.txt'
# censorship_filename = result_path
# test_domain_dic = dict()
# with open(censorship_filename, 'r') as censorship_file:
#     for entry in censorship_file:
#         if 'timeout' in entry:
#             entry_dic = json.loads(entry.strip())
#             domain = entry_dic['domain']
#             countryCode = entry_dic['probe']['countryCode']
#             if countryCode not in useless_country_list:
#                 if domain in test_domain_dic.keys():
#                     test_domain_dic[domain].append(countryCode)
#                 else:
#                     test_domain_dic[domain] = [countryCode]



# dns_server = '3.82.214.39'
# protocol = 'UDP'
# log_file = '../results/ripe_atlas/additional_measurement.txt'

# for domain in tqdm.tqdm(test_domain_dic.keys()):
#     country_code_list = test_domain_dic[domain]
#     target_domain = domain
#     is_success, measuremment_id = schedule_dns_measurement(dns_server, target_domain, protocol, country_code_list)
#     if is_success:
#         entry = str(datetime.datetime.now()) + '\t' + target_domain + ' \t' + str(measuremment_id) + '\n'
#         with open(log_file, 'a+') as f:
#             f.write(entry)
#         time.sleep(60)
#     else:
#         sys.exit(0)

###################################################################### schedule measurements additional ############################################################





##################################################################### retrieve measurements ############################################################
output_file = '../results/ripe_atlas/ripe_atlas_iran_results.txt'
exist_domain_list = list()
with open(output_file, 'r') as f:
    entries = f.read().strip().split('\n')
    for entry in entries:
        temp_dic = json.loads(entry)
        if temp_dic['domain'] not in exist_domain_list:
            exist_domain_list.append(temp_dic['domain'])
        

with open('../results/ripe_atlas/iran_additional_measurement_2.txt') as f:
    entries = f.read().strip().split('\n')
    domains = list(map(lambda x: x.split()[2], entries))
    measuremment_ids = list(map(lambda x: x.split()[3], entries))

for i in tqdm.tqdm(range(len(domains))):
    domain = domains[i]
    measuremment_id = measuremment_ids[i]
    if domain in exist_domain_list:
        continue

    while True:
        is_success, results = retrieve_measurement_result(measuremment_id)
        if is_success:
            # time.sleep(0.5)
            break
        else:
            time.sleep(1)

    for result in results:
        result = dict(result)
        probe = result['from']
        result_dic = dict()
        result_dic['probe'] = probe
        result_dic['domain'] = domain
        result_dic['protocol'] = result['proto']
        result_dic['measuremend_id'] = result['msm_id']
        result_dic['error'] = ''
        result_dic['rcode'] = -1
        result_dic['ip_list'] = list()
        if 'error' in result.keys():
            result_dic['error'] = result['error']
        else:
            try:
                rcode, ip_list = process_raw_dns_response(result['result']['abuf'])
                result_dic['rcode'] = rcode
                result_dic['ip_list'] = ip_list
            except:
                result_dic['error'] = 'error dns format'
        
        json_string = json.dumps(result_dic)
        with open(output_file, 'a+') as output:
            output.write(json_string + '\n')





input_file = '../results/ripe_atlas/ripe_atlas_iran_results.txt'
output_file = '../results/ripe_atlas/ripe_atlas_iran_results_updated.txt'

ip_info_dic = dict()
with open(input_file, 'r') as f:
    entries = f.read().strip().split('\n')
    for entry in entries:
        temp_dic = json.loads(entry)
        ip = temp_dic['probe']
        if ip not in ip_info_dic.keys():
            while True:
                try:
                    response = os.popen('curl -m 10 -s http://ip-api.com/json/' + ip).read()
                    probe_info = json.loads(response)
                    ip_info_dic[ip] = probe_info
                    time.sleep(2)
                    break
                except:
                    print('problem ip: ', ip)
                    time.sleep(10)

        probe_info = ip_info_dic[ip]
        temp_dic['probe'] = probe_info

        json_string = json.dumps(temp_dic)
        with open(output_file, 'a+') as output:
            output.write(json_string + '\n')
        
# ###################################################################### retrieve measurements ############################################################
        











###################################################################### schedule measurements ############################################################

# country_code_list = ["AE","AF","AG","AL","AM","AO","AR","AS","AT","AU","AZ","BA","BB","BD","BE","BG","BH","BI","BN","BO","BR","BS","BW","BY","BZ","CA","CD","CG","CH","CI","CL","CN","CO","CR","CU","CW","CY","CZ","DE","DK","DO","DZ","EC","EE","EG","ES","FI","FJ","FR","GB","GE","GH","GM","GQ","GR","GT","GU","HK","HN","HR","HU","ID","IE","IL","IN","IQ","IR","IS","IT","JM","JO","JP","KE","KG","KH","KR","KW","KZ","LA","LB","LK","LT","LV","LY","MA","MD","ME","MG","MN","MO","MP","MT","MU","MV","MW","MX","MY","NA","NC","NE","NG","NI","NL","NO","NP","NZ","OM","PA","PE","PF","PG","PH","PK","PL","PR","PS","PT","PW","PY","QA","RE","RO","RS","RU","SA","SB","SD","SE","SG","SI","SK","SN","SR","ST","SV","SY","TH","TN","TR","TT","TW","TZ","UA","UG","UY","UZ","VE","VI","VN","ZA","ZM"]

# dns_server = '3.93.242.26'
# protocol = 'UDP'
# log_file = '../results/ripe_atlas/finished_measurement.txt'


# with open(log_file, 'r') as f:
#     raw_file = f.read()
#     if raw_file != '':
#         finished_domain_list = raw_file.strip().split('\n')
#         finished_domain_list = list(map(lambda x: x.split()[2], finished_domain_list))
#     else:
#         finished_domain_list = list()

# target_domain_list = retrieve_test_list()
# target_domain_list = list(filter(lambda x: x not in finished_domain_list, target_domain_list))
# random.shuffle(target_domain_list)
# target_domain_list = target_domain_list[:(1000 - len(finished_domain_list))]



# for target_domain in target_domain_list:

#     is_success, measuremment_id = schedule_dns_measurement(dns_server, target_domain, protocol, country_code_list)

#     if is_success:
#         entry = str(datetime.datetime.now()) + '\t' + target_domain + ' \t' + str(measuremment_id) + '\n'
#         with open(log_file, 'a+') as f:
#             f.write(entry)
#         time.sleep(270)
#     else:
#         sys.exit(0)

###################################################################### schedule measurements ############################################################
        


###################################################################### retrieve measurements ############################################################
# output_file = '../results/ripe_atlas/ripe_atlas_results.txt'
# exist_domain_list = list()
# with open(output_file, 'r') as f:
#     entries = f.read().strip().split('\n')
#     for entry in entries:
#         temp_dic = json.loads(entry)
#         if temp_dic['domain'] not in exist_domain_list:
#             exist_domain_list.append(temp_dic['domain'])
        

# with open('../results/ripe_atlas/finished_measurement.txt') as f:
#     entries = f.read().strip().split('\n')
#     domains = list(map(lambda x: x.split()[2], entries))
#     measuremment_ids = list(map(lambda x: x.split()[3], entries))

# for i in tqdm.tqdm(range(1000)):
#     domain = domains[i]
#     measuremment_id = measuremment_ids[i]
#     if domain in exist_domain_list:
#         continue

#     while True:
#         is_success, results = retrieve_measurement_result(measuremment_id)
#         if is_success:
#             time.sleep(1)
#             break
#         else:
#             time.sleep(10)

#     for result in results:
#         result = dict(result)
#         probe = result['from']
#         result_dic = dict()
#         result_dic['probe'] = probe
#         result_dic['domain'] = domain
#         result_dic['protocol'] = result['proto']
#         result_dic['measuremend_id'] = result['msm_id']
#         result_dic['error'] = ''
#         result_dic['rcode'] = -1
#         result_dic['ip_list'] = list()
#         if 'error' in result.keys():
#             result_dic['error'] = result['error']
#         else:
#             try:
#                 rcode, ip_list = process_raw_dns_response(result['result']['abuf'])
#                 result_dic['rcode'] = rcode
#                 result_dic['ip_list'] = ip_list
#             except:
#                 result_dic['error'] = 'error dns format'
        
#         json_string = json.dumps(result_dic)
#         with open(output_file, 'a+') as output:
#             output.write(json_string + '\n')

###################################################################### retrieve measurements ############################################################


###################################################################### update probe info ############################################################
# input_file = '../results/ripe_atlas/ripe_atlas_results.txt'
# output_file = '../results/ripe_atlas/ripe_atlas_results_updated.txt'

# ip_info_dic = dict()
# with open(input_file, 'r') as f:
#     entries = f.read().strip().split('\n')
#     for entry in entries:
#         temp_dic = json.loads(entry)
#         ip = temp_dic['probe']
#         if ip not in ip_info_dic.keys():
#             while True:
#                 try:
#                     response = os.popen('curl -m 10 -s http://ip-api.com/json/' + ip).read()
#                     probe_info = json.loads(response)
#                     ip_info_dic[ip] = probe_info
#                     time.sleep(2)
#                     break
#                 except:
#                     print('problem ip: ', ip)
#                     time.sleep(10)

#         probe_info = ip_info_dic[ip]
#         temp_dic['probe'] = probe_info

#         json_string = json.dumps(temp_dic)
#         with open(output_file, 'a+') as output:
#             output.write(json_string + '\n')
        
        
        
            
###################################################################### update probe info ############################################################
