import os
import json
import requests

def unpack_proxy_args(proxy):
    proxy_address = proxy['proxy_address']
    proxy_port = proxy['proxy_port']
    username = proxy['username']
    password = proxy['password']
    return proxy_address, proxy_port, username, password



def get_curl_cmd(proxy, url):
    proxy_address, proxy_port, username, password = unpack_proxy_args(proxy)
    return 'curl -m 10 -s -x ' + proxy_address + ':' + str(proxy_port) + ' -U ' + username + ':' + password + ' ' + url


def get_proxy_stats(proxy, timeout = 5):
    url = 'http://api.proxyrack.net/stats'
    curl_cmd = get_curl_cmd(proxy, url)
    try:
        stats = os.popen(curl_cmd).read()
        response = json.loads(stats)
    except:
        response = None
    
    return response



def release_exit_node(proxy, timeout = 5):
    url = 'http://api.proxyrack.net/release'
    curl_cmd = get_curl_cmd(proxy, url)

    flag = False
    try:
        response = os.popen(curl_cmd).read()
        
        if 'true' in response:
            flag = True
    except:
        pass
    
    return flag



def get_proxy_info(proxy, timeout = 5):
    url = 'http://ip-api.com/json'
    curl_cmd = get_curl_cmd(proxy, url)

    try:
        response = os.popen(curl_cmd).read()
        response = json.loads(response)
    except:
        response = None

    return response



def get(proxy, url, header = {}, timeout = 5):
    proxy_address, proxy_port, username, password = unpack_proxy_args(proxy)
    proxies = {
        "https":"socks5h://{}:{}@{}".format(username, password, proxy_address + ':' + str(proxy_port)),
        "http":"socks5h://{}:{}@{}".format(username, password, proxy_address + ':' + str(proxy_port))
        }
    try:
        response = requests.get(url, proxies=proxies, headers = header, timeout = timeout) 
    except:
        response = None
    
    return response