import urllib.parse
import os
import ipaddress
import proxy_request
import proxyrack
import random
import joblib
import datetime
import json
import time
import setup

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



def build_finished_countries_file(finished_countries_file):
    if not os.path.isfile(finished_countries_file):
        with open(log_file_path + 'proxyrack_finished_countries_init.json') as init_f:
            raw = init_f.read()
            with open(finished_countries_file, 'w') as f:
                f.write(raw)
    


def get_proxyrack_proxy_info(proxy, finished_countries):

    release_time = 0
    for _ in range(300):
        
        need_release = False
        proxy_info = proxyrack.get_proxy_info(proxy)

        if proxy_info != None:
            test_sequence = ['dns', 'http', 'sni']
            test_sequence = list(filter(lambda x: finished_countries[x].get(proxy_info['country'], 0) < max_per_country, test_sequence))
            if len(test_sequence) != 0:
                break
            else:
                need_release = True
        else:
            need_release = True
        
        if need_release:
            proxyrack.release_exit_node(proxy)
            release_time += 1
            if release_time % 100 == 0:
                log = str(datetime.datetime.now()) + '\t' + 'release reached: ' + str(release_time) + '\t' + 'sleeping 30 minutes ......\n'
                add_log(log_file_name, log)
                time.sleep(1800)

    if release_time == 300:
        log = str(datetime.datetime.now()) + '\t' + 'Cannot find a usable proxy in proxyrack!'
        add_log(log_file_name, log)
        raise Exception('Cannot find a usable proxy in proxyrack')

    return proxy_info, test_sequence





def is_proxy_ok(proxy, proxy_info, results, test):
    proxy_ok = True

    # test without proxy
    if proxy == dict():
        return proxy_ok

    validation_error = 0
    success_result = 0
    for result in results:
        domain, test_result = result
        if test_result['status'] == 'success' and domain not in validation_domain:
            success_result += 1
        if domain in validation_domain:
            if test == 'dns':
                if test_result['ip_list'] == ['100.100.100.100']:
                    success_result += 1
                else:
                    validation_error += 1
            if test == 'http':
                if 'linjin@udel.edu' in test_result['text']:
                    success_result += 1
                else:
                    validation_error += 1

            if test == 'sni':
                if test_result['cert_serial'] == '0':
                    validation_error += 1
                elif test_result['cert_serial'] != '201614099203817838842043426670715639081255164964' and test_result['cert_serial'] != '85723161702102284164881707705813409552803205256':
                    if test_result['http_result']['text'] == 'sni\n':
                        success_result += 1
                    else:
                        validation_error += 1
                else:
                    success_result += 1

                
        # if test_result['status'] == 'fail' and domain in validation_domain:
        #     validation_error += 1
    
    success_rate = success_result / len(results)

    if len(results) > 2000 and success_rate < 0.5:
        proxy_ok = False
        log = str(datetime.datetime.now()) + '\t' + 'First round, success rate low!' + '\t' + 'success_rate: ' + str(float('%0.2f' % success_rate))
        add_log(log_file_name, log)
    
    if validation_error == len(validation_domain):
        proxy_ok = False
        log = str(datetime.datetime.now()) + '\t' + 'Self validation error!' + '\t' + 'success_rate: ' + str(float('%0.2f' % success_rate))
        add_log(log_file_name, log)

    if proxy_ok:
        validation = 0
        for _ in range(validation_retry):
            proxy_info_test = proxyrack.get_proxy_info(proxy)

            if proxy_info != proxy_info_test and proxy_info_test != None:
                proxy_ok = False
                log = str(datetime.datetime.now()) + '\t' + 'Proxy info does not match!' + '\t' + 'New proxy: ' + proxy_info_test['country'] + '\t' + proxy_info_test['query']
                add_log(log_file_name, log)
                break
            
            if proxy_info_test == None:
                validation += 1
                if validation == validation_retry:
                    proxy_ok = False
                    log = str(datetime.datetime.now()) + '\t' + 'Proxy goes down!' + '\t' + 'success_rate: ' + str(float('%0.2f' % success_rate))
                    add_log(log_file_name, log)
                    break
                if success_rate == 1:
                    log = str(datetime.datetime.now()) + '\t' + 'Go on!' + '\t' + 'success_rate: ' + str(float('%0.2f' % success_rate))
                    add_log(log_file_name, log)
                    break
                elif success_rate > 0.8:
                    log = str(datetime.datetime.now()) + '\t' + 'Proxy info is None' + '\t' + 'success_rate: ' + str(float('%0.2f' % success_rate)) + '\t' + 'sleeping 10 seconds'
                    add_log(log_file_name, log)
                    time.sleep(10)
                elif len(results) < 1000:
                    log = str(datetime.datetime.now()) + '\t' + 'Proxy info is None' + '\t' + 'results_lenght: ' + str(len(results)) + '\t' + 'sleeping 10 seconds'
                    add_log(log_file_name, log)
                    time.sleep(10)
                else:
                    time.sleep(1)

    return proxy_ok




def local_cache_test(proxy):
    has_cache = False
    domain = 'a.test.dnsexp.xyz'

    # cache phase
    cache_dns_result = proxy_request.proxy_dns(domain, dns_validation_server, proxy=proxy, timeout=timeout)
    # cache failure, drop proxy
    if cache_dns_result[1]['ip_list'] != dns_validation_result:
        has_cache = True

    cache_http_result = proxy_request.proxy_http(domain, http_validation_server, proxy=proxy, timeout=timeout)
    # cache failure, drop proxy
    if cache_http_result[1]['text'] != http_validation_result:
        has_cache = True
    
    # test phase
    if not has_cache:
        test_dns_result = proxy_request.proxy_dns(domain, dns_server, proxy=proxy, timeout=timeout)
        if test_dns_result[1]['ip_list'] != ['100.100.100.100']:
            has_cache = True

        test_http_result = proxy_request.proxy_http(domain, http_server, proxy=proxy, timeout=timeout)
        if 'linjin@udel.edu' not in test_http_result[1]['text']:
            has_cache = True

    return has_cache



platform = 'proxyrack'
proxy, concurrency, \
    result_path, result_suffix, cert_filename, finished_countries_file, log_file_path, \
        validation_retry, validation_domain, dns_validation_result, http_validation_result, dns_validation_server, http_validation_server, \
            dns_server, http_server, sni_server, \
                timeout, retry, max_per_country = setup.setup(platform)



pid = os.getpid()
start_date = str(datetime.date.today())
#start_date = '2021-07-26'

finished_countries_file = log_file_path + start_date + '_' + finished_countries_file
build_finished_countries_file(finished_countries_file)
log_file_name = log_file_path + start_date + '_pid_' + str(pid) + '.log'


log = str(datetime.datetime.now()) + '\t' + 'test start!'
add_log(log_file_name, log)
log = str(datetime.datetime.now()) + '\t' + 'proxy_port: ' + str(proxy['proxy_port']) + '\t' + 'concurrency: ' + str(concurrency) + '\t' + 'sni_server: ' + str(sni_server)
add_log(log_file_name, log)



start = time.time()
while True:
    end = time.time()
    if end - start > 86400 * 7:
        break

    with open(finished_countries_file, 'r') as f:
        finished_countries = json.loads(f.read())
    
    proxy_info, test_sequence = get_proxyrack_proxy_info(proxy,finished_countries)

    random.shuffle(test_sequence)
    log = str(datetime.datetime.now()) + '\t' + str(proxy_info)
    add_log(log_file_name, log)

    has_cache = local_cache_test(proxy)
    if has_cache:
        proxyrack.release_exit_node(proxy)
        log = str(datetime.datetime.now()) + '\t' + 'Cache test failure' + '\t' + 'Proxyrack proxy released!\n'
        add_log(log_file_name, log)
        continue

    log = str(datetime.datetime.now()) + '\t' + 'test_sequence' + '\t' + str(test_sequence)
    add_log(log_file_name, log)


    test_list = retrieve_test_list(proxy_info['countryCode'])

    result_dic = dict()
    for test in test_sequence:
        result_dic[test] = dict()
        result_dic[test]['platform'] = platform
        result_dic[test]['proxy'] = dict(proxy_info)
        result_dic[test]['domain'] = dict()
        result_dic[test]['finished'] = False

        for domain in test_list:
            result_dic[test]['domain'][domain] = list()
    
    proxy_ok = True

    for test in test_sequence:
        while True:
            test_list = refresh_test_list(result_dic, test)
            log = str(datetime.datetime.now()) + '\t' + test + '\t' + str(len(test_list))
            add_log(log_file_name, log)

            if len(test_list) == 0:
                result_dic[test]['finished'] = True
                
                with open(finished_countries_file, 'r') as f:
                    finished_countries = json.loads(f.read())
                    finished_countries[test][proxy_info['country']] = finished_countries[test].get(proxy_info['country'], 0) + 1
                with open(finished_countries_file, 'w') as f:
                    json_string = json.dumps(finished_countries)
                    f.write(json_string)

                with open(result_path + start_date + '_' + test + result_suffix, 'a+') as result_file:
                    json_string = json.dumps(result_dic[test])
                    result_file.write(json_string + '\n')
                    
                    log = str(datetime.datetime.now()) + '\t' + test + '\t' + 'result saved!'
                    add_log(log_file_name, log)
                
                break
            
            
            test_list += validation_domain
            random.shuffle(test_list)
            
            
            if test == 'dns':
                results = joblib.Parallel(n_jobs = concurrency,  backend="threading") (joblib.delayed(proxy_request.proxy_dns) (domain, dns_server, proxy=proxy, timeout=timeout) for domain in test_list)
            elif test == 'http':
                results = joblib.Parallel(n_jobs = concurrency,  backend="threading") (joblib.delayed(proxy_request.proxy_http) (domain, http_server, proxy=proxy, timeout=timeout) for domain in test_list)
            elif test == 'sni':
                results = joblib.Parallel(n_jobs = concurrency,  backend="threading") (joblib.delayed(proxy_request.proxy_sni) (domain, sni_server, proxy=proxy, timeout=timeout) for domain in test_list)
            else:
                pass


            proxy_ok = is_proxy_ok(proxy, proxy_info, results, test)
            if not proxy_ok:
                break
            

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
        
        if not proxy_ok:
            log = str(datetime.datetime.now()) + '\t' + 'Proxy failed, changing another one...'
            add_log(log_file_name, log)
            break
    
    proxyrack.release_exit_node(proxy)
    log = str(datetime.datetime.now()) + '\t' + 'Proxyrack proxy released!\n'
    add_log(log_file_name, log)

    #break
log = str(datetime.datetime.now()) + '\t' + 'Test finished!'
add_log(log_file_name, log)