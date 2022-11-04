import random


def setup():


    proxyrack_proxy = dict()
    proxyrack_proxy['username'] = ''
    proxyrack_proxy['password'] = ''
    proxyrack_proxy['proxy_address'] = 'megaproxy.rotating.proxyrack.net'
    lower_port = 10000
    upper_port = 10249
    proxyrack_proxy['proxy_port'] = random.randint(lower_port, upper_port)
    proxy = proxyrack_proxy
    concurrency = 20

    # define the result path
    result_path = './'
    result_suffix = '_proxyrack_censorship_json.txt'
    cert_filename = 'proxyrack_certs.json'
    finished_countries_file = 'finished_countries.json'
    log_file_path = './'

    timeout = 15

    # control servers
    dns_server = ''
    http_server = ''
    sni_server = ''
    sni_server = ''


    validation_retry = 2
    validation_domain = ['']
    retry = 5
    max_per_country = 15

    dns_validation_result = ['']
    http_validation_result = ''

    dns_validation_server = ''
    http_validation_server = ''

    return proxy, concurrency, \
        result_path, result_suffix, cert_filename, finished_countries_file, log_file_path, \
            validation_retry, validation_domain, dns_validation_result, http_validation_result, dns_validation_server, http_validation_server, \
                dns_server, http_server, sni_server, \
                    timeout, retry, max_per_country

