import urllib.parse
import os
import ipaddress
import proxy_request
import random
import joblib
import datetime
import json
import time
import setup
import sys



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



def refresh_test_list(result_dic, test):
    test_list = list()
    for domain in result_dic[test]['domain'].keys():
        result_list = result_dic[test]['domain'][domain]
        status_list = list(set(map(lambda x: x['status'], result_list)))
        if 'success' not in status_list and len(result_list) < retry:
            test_list.append(domain)
    return test_list



def add_log(log_file_name, log):
    with open(log_file_name, 'a+') as log_file:
        log_file.write(log + '\n')



def get_vpn_info():
    url = 'http://ip-api.com/json'
    curl_cmd = 'curl -m 10 -s ' + url

    try:
        response = os.popen(curl_cmd).read()
        response = json.loads(response)
    except:
        response = None

    return response


def is_ip_blocked(test):
    domain = 'a.edu'
    if test == 'dns':
        result = proxy_request.proxy_dns(domain, dns_server, proxy=proxy, timeout=timeout)
    if test == 'http':
        result = proxy_request.proxy_http(domain, http_server, proxy=proxy, timeout=timeout)
    if test == 'sni':
        result = proxy_request.proxy_sni(domain, sni_server, proxy=proxy, timeout=timeout)
    
    domain, test_result = result
    if test_result['status'] == 'success':
        ip_blocked = False
    else:
        ip_blocked = True

    return ip_blocked



platform = 'vpn'
proxy, concurrency, \
    result_path, result_suffix, cert_filename, finished_countries_file, log_file_path, \
        validation_retry, validation_domain, \
            _, _, _, _, \
            dns_server, http_server, sni_server, \
                timeout, retry, max_per_country = setup.setup(platform)



pid = os.getpid()
start_date = str(datetime.date.today())


log_file_name = log_file_path + start_date + '_pid_' + str(pid) + '.log'

log = str(datetime.datetime.now()) + '\t' + 'test start!'
add_log(log_file_name, log)
log = str(datetime.datetime.now()) + '\t' + 'concurrency: ' + str(concurrency)
add_log(log_file_name, log)


vpn_info = get_vpn_info()
test_sequence = ['dns', 'http', 'sni']
test_sequence = ['http', 'sni']


log = str(datetime.datetime.now()) + '\t' + str(vpn_info)
add_log(log_file_name, log)
log = str(datetime.datetime.now()) + '\t' + 'test_sequence' + '\t' + str(test_sequence)
add_log(log_file_name, log)


test_list = retrieve_test_list(vpn_info['countryCode'])

result_dic = dict()
for test in test_sequence:
    result_dic[test] = dict()
    result_dic[test]['platform'] = platform
    result_dic[test]['proxy'] = dict(vpn_info)
    result_dic[test]['domain'] = dict()
    result_dic[test]['finished'] = False

    for domain in test_list:
        result_dic[test]['domain'][domain] = list()



for test in test_sequence:
    log = str(datetime.datetime.now()) + '\t' + test + '\t' + str(len(test_list))
    add_log(log_file_name, log)

    random.shuffle(test_list)
    
    results = list()
    ip_blocked = False
    for domain in test_list:
        
        while True:
            if ip_blocked:
                if test == 'dns':
                    log = str(datetime.datetime.now()) + '\t' + 'sleep 1 second ......'
                    add_log(log_file_name, log)
                    time.sleep(1)
                else:
                    log = str(datetime.datetime.now()) + '\t' + 'sleep 100 second ......'
                    add_log(log_file_name, log)
                    time.sleep(100)
                
                ip_blocked = is_ip_blocked(test)
                if not ip_blocked:
                    ip_blocked = False
            else:
                break
        
        if test == 'dns':
            result = proxy_request.proxy_dns(domain, dns_server, proxy=proxy, timeout=timeout)
        elif test == 'http':
            result = proxy_request.proxy_http(domain, http_server, proxy=proxy, timeout=timeout)
        elif test == 'sni':
            result = proxy_request.proxy_sni(domain, sni_server, proxy=proxy, timeout=timeout)
        else:
            pass
        
        domain, test_result = result
        log = str(datetime.datetime.now()) + '\t' + domain + '\t' + test_result['status']
        add_log(log_file_name, log)
        results.append(result)
        if test_result['status'] == 'success':
            ip_blocked = False
        else:
            ip_blocked = True



    if test == 'dns' or test == 'http':
        for result in results:
            domain, test_result = result
            if domain not in validation_domain:
                result_dic[test]['domain'][domain].append(test_result)

    if test == 'sni':
        cert_dic = dict()
        for result in results:
            domain, sni_result = result
            if domain not in validation_domain:
                cert = sni_result.pop('cert')
                cert_serial = sni_result['cert_serial']
                cert_dic[cert_serial] = cert

                result_dic[test]['domain'][domain].append(sni_result)

        try:
            with open(cert_filename, 'r') as cert_file:
                cert_database = cert_file.read()
        except:
            with open(cert_filename, 'w') as cert_file:
                cert_file.write(json.dumps(cert_dic))
        else:
            cert_database = json.loads(cert_database, strict=False)
            cert_database.update(cert_dic)
            with open(cert_filename, 'w') as cert_file:
                cert_file.write(json.dumps(cert_database) + '\n')
    
            result_dic[test]['finished'] = True

    with open(result_path + start_date + '_china_' + test + result_suffix, 'a+') as result_file:
        json_string = json.dumps(result_dic[test])
        result_file.write(json_string + '\n')
        
        log = str(datetime.datetime.now()) + '\t' + test + '\t' + 'result saved!\n'
        add_log(log_file_name, log)

log = str(datetime.datetime.now()) + '\t' + 'Test finished!'
add_log(log_file_name, log)