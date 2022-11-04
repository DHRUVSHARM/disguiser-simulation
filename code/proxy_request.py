import socket
import socks
import dns.query
import dns.message
import dns.name
import dns.rdatatype
import requests
import ssl
import base64
import struct
import OpenSSL
import time
import random
from io import BytesIO
from http.client import HTTPResponse


def unpack_proxy_args(proxy):
    through_proxy = False
    proxy_address, proxy_port, username, password = ('', 0, '', '')
    if proxy != {}:
        through_proxy = True
        proxy_address = proxy['proxy_address']
        proxy_port = proxy['proxy_port']
        username = proxy['username']
        password = proxy['password']

    return through_proxy, proxy_address, proxy_port, username, password



############################################# DNS Part ##########################################
def extract_ip_address(dns_response):
    ip_list = list()
    for rrset in dns_response.answer:
        if rrset.rdtype == dns.rdatatype.A:
            for rr in rrset:
                ip_list.append(rr.address)
    return ip_list



def process_raw_dns_response(raw_dns_response, is_timeout):
    dns_result = dict()
    dns_result['timestamp'] = int(time.time())
    dns_result['status'] = 'success'
    dns_result['rcode'] = -1
    dns_result['ip_list'] = list()
    dns_result['is_timeout'] = is_timeout

    if not is_timeout:
        try:
            response_length = struct.unpack('!H', raw_dns_response[:2])[0]
            assert len(raw_dns_response[2:]) == response_length
        
        except:
            dns_result['status'] = 'fail'
        
        else:
            try:
                dns_response = dns.message.from_wire(raw_dns_response[2:])
                rcode = dns_response.rcode()
                dns_result['rcode'] = rcode
                
                if rcode == 0:
                    ip_list = extract_ip_address(dns_response)
                    dns_result['ip_list'] = ip_list
            except:
                pass
    else:
        dns_result['status'] = 'fail'

    return dns_result



def proxy_dns(domain, server, proxy = {}, timeout = 5):
    through_proxy, proxy_address, proxy_port, username, password = unpack_proxy_args(proxy)

    qname = dns.name.from_text(domain)
    q = dns.message.make_query(qname, dns.rdatatype.A).to_wire()
    q = struct.pack('!H', len(q)) + q # prepend 2 bytes packet length

    # set up tcp socket 
    if through_proxy:
        sock = socks.socksocket()
        sock.set_proxy(socks.SOCKS5, proxy_address, proxy_port, rdns = True, username = username, password = password)
        sock.settimeout(timeout)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
    
    try:    
        # tcp handshake
        sock.connect((server, 53))

        # send DNS-over-TCP query, receive response
        sock.send(q)
        raw_dns_response = sock.recv(1024)

        # close socket
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

        is_timeout = False
    
    except socket.timeout:
        raw_dns_response = ''
        is_timeout = True
    except:
        raw_dns_response = ''
        is_timeout = False

    dns_result = process_raw_dns_response(raw_dns_response, is_timeout)

    return domain, dns_result



############################################# HTTP Part ##########################################
def process_raw_http_response(raw_http_response, is_timeout):
    http_result = dict()
    http_result['timestamp'] = int(time.time())
    http_result['status'] = 'success'
    http_result['status_code'] = 0
    http_result['url'] = ''
    http_result['text'] = ''
    http_result['headers'] = dict()
    http_result['is_timeout'] = is_timeout

    if not is_timeout:
        if raw_http_response == '':
            http_result['status'] = 'fail'
        else:
            http_result['text'] = raw_http_response.text
            http_result['url'] = raw_http_response.url
            http_result['status_code'] = raw_http_response.status_code
            http_result['headers'] = dict(raw_http_response.headers)
    else:
        http_result['status'] = 'fail'

    return http_result



def proxy_http(domain, server, proxy = {}, timeout = 5):
    through_proxy, proxy_address, proxy_port, username, password = unpack_proxy_args(proxy)
    
    if through_proxy:
        proxy = {"http":"socks5h://{}:{}@{}".format(username, password, proxy_address + ':' + str(proxy_port))}
    else:
        proxy = {}

    headers = dict()
    headers['Host'] = domain
    headers['User-Agent'] = 'Mozilla/5.0'
    
    url = 'http://' + server
    try:
        raw_http_response = requests.get(url, proxies=proxy, headers = headers, timeout = timeout)

        is_timeout = False
    
    except requests.exceptions.Timeout:
        raw_http_response = ''
        is_timeout = True

    except:
        raw_http_response = ''
        is_timeout = False

    
    http_result = process_raw_http_response(raw_http_response, is_timeout)

    return domain, http_result



############################################# SNI Part ##########################################
def process_raw_http_response_from_sni(raw_http_response, is_timeout):
    http_result = dict()
    http_result['timestamp'] = int(time.time())
    http_result['status'] = 'success'
    http_result['status_code'] = 0
    #http_result['url'] = ''
    http_result['text'] = ''
    http_result['headers'] = dict()
    http_result['is_timeout'] = is_timeout

    class FakeSocket():
        def __init__(self, response_bytes):
            self._file = BytesIO(response_bytes)
        def makefile(self, *args, **kwargs):
            return self._file

    if not is_timeout:
        if raw_http_response == b'':
            http_result['status'] = 'fail'
        else:
            try:
                source = FakeSocket(raw_http_response)
                response = HTTPResponse(source)
                response.begin()
                http_result['text'] = response.read(len(raw_http_response)).decode()
                http_result['status_code'] = response.status
                http_result['headers'] = dict(response.getheaders())
            except:
                pass
    else:
        http_result['status'] = 'fail'

    return http_result


def recvall(sock):
    data = b''
    bufsize = 4096
    while True:
        packet = sock.recv(bufsize)
        data += packet
        if len(packet) < bufsize:
            break
    return data
    
    
def proxy_sni(domain, server, proxy = {}, timeout = 5):
    through_proxy, proxy_address, proxy_port, username, password = unpack_proxy_args(proxy)
    
    # set up tcp socket 
    if through_proxy:
        sock = socks.socksocket()
        sock.set_proxy(socks.SOCKS5, proxy_address, proxy_port, rdns = True, username = username, password = password)
        sock.settimeout(timeout)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)

    sni_result = dict()
    sni_result['timestamp'] = int(time.time())
    sni_result['cert'] = ''
    sni_result['cert_serial'] = '0'
    sni_result['status'] = 'success'
    sni_result['is_timeout'] = False
    
    try:
        sock.connect((server, 443))
        wrapped_socket = context.wrap_socket(sock, server_hostname = domain)
        
    except socket.timeout:
        sni_result['status'] = 'fail'
        sni_result['is_timeout'] = True
    
    except:
        sni_result['status'] = 'fail'
    
    else:
        try:
            sni_result['cert'] = ssl.DER_cert_to_PEM_cert(wrapped_socket.getpeercert(True))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, sni_result['cert'])
            sni_result['cert_serial'] = str(x509.get_serial_number())


            if sni_result['cert_serial'] != '201614099203817838842043426670715639081255164964' and sni_result['cert_serial'] != '85723161702102284164881707705813409552803205256' and sni_result['cert_serial'] != '0':
                request = "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n\r\n" % domain
                request = request.encode()
                wrapped_socket.send(request)

                try:
                    raw_http_response = recvall(wrapped_socket)
                    is_http_timeout = False
                except socket.timeout:
                    raw_http_response = b''
                    is_http_timeout = True
                except:
                    raw_http_response = b''
                    is_http_timeout = False
                
                http_result = process_raw_http_response_from_sni(raw_http_response, is_http_timeout)
                sni_result['http_result'] = http_result
        except Exception as e:
            print('proxy_sni_error:', e)
            pass


    try:
        wrapped_socket.shutdown(socket.SHUT_RDWR)
        wrapped_socket.close()
    except:
        pass

    return domain, sni_result