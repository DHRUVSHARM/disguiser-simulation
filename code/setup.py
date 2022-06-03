import random


def setup(platform):

    if platform == 'proxyrack':
        # proxyrack proxy setup
        proxyrack_proxy = dict()
        proxyrack_proxy['username'] = 'linjin'
        proxyrack_proxy['password'] = 'd16dc4-8d5895-7a81c6-df52b2-ae9182'
        proxyrack_proxy['proxy_address'] = 'megaproxy.rotating.proxyrack.net'
        lower_port = 10000
        upper_port = 10249
        proxyrack_proxy['proxy_port'] = random.randint(lower_port, upper_port)
        proxy = proxyrack_proxy
        concurrency = 20
        result_path = '../results/proxyrack/'
        result_suffix = '_proxyrack_censorship_json.txt'
        cert_filename = '../results/proxyrack/proxyrack_certs.json'
        finished_countries_file = 'proxyrack_finished_countries.json'
        log_file_path = '../results/proxyrack/'
        timeout = 15
        dns_server = '184.73.92.183'
        http_server = '100.26.203.116'
        sni_server = '54.166.38.207'
        sni_server = '54.235.225.189'
    
    
    # if platform == 'tor':
    #     # tor proxy setup
    #     tor_proxy = dict()
    #     tor_proxy['username'] = ''
    #     tor_proxy['password'] = ''
    #     tor_proxy['proxy_address'] = '127.0.0.1'
    #     tor_proxy['proxy_port'] = 9050
    #     proxy = tor_proxy
    #     concurrency = 50
    #     result_path = '../results/tor/'
    #     result_suffix = '_tor_censorship_json.txt'
    #     cert_filename = '../results/tor/tor_certs.json'
    #     finished_countries_file = 'tor_finished_countries.json'
    #     log_file_path = '../results/tor/'
    #     timeout = 10
    #     dns_server = '3.91.105.244'
    #     http_server = '52.91.166.212'
    #     sni_server = '3.80.202.200'
    
    if platform == 'vpn':
        proxy = dict()
        concurrency = 50
        result_path = '../results/vpn/'
        result_suffix = '_vpn_censorship_json.txt'
        cert_filename = '../results/vpn/vpn_certs.json'
        finished_countries_file = ''
        log_file_path = '../results/vpn/'
        timeout = 5
        dns_server = '3.91.105.244'
        http_server = '52.91.166.212'
        sni_server = '18.207.203.33'
        #sni_server = '3.80.202.200'
    
    validation_retry = 2
    validation_domain = ['a.dnsexp.xyz', 'b.dnsexp.xyz', 'c.dnsexp.xyz']
    retry = 5
    max_per_country = 15

    dns_validation_result = ['128.4.12.93']
    http_validation_result = 'validation\n'

    dns_validation_server = '18.212.239.20'
    http_validation_server = '3.214.184.86'

    return proxy, concurrency, \
        result_path, result_suffix, cert_filename, finished_countries_file, log_file_path, \
            validation_retry, validation_domain, dns_validation_result, http_validation_result, dns_validation_server, http_validation_server, \
                dns_server, http_server, sni_server, \
                    timeout, retry, max_per_country

