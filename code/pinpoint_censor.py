import socket
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
import joblib
import os
import sys
from io import BytesIO
from http.client import HTTPResponse
from socket import error as SocketError
import errno




def traceroute(ip_addr):
	command = 'traceroute -n -q 1 -m 40 -w 1 ' + ip_addr
	result = os.popen(command).read()
	route = [item.strip() for item in result.strip().split('\n')]
	#route = filter(lambda x: netaddr.valid_ipv4(x.split()[1]), route)

	return route





# ICMP format in IP packet
# data[:20] is IP header
# data[20:24] is ICMP header: data[20:21] is type and when type == 11, Time-to-Live Exceeded
# data[24:28] unused
# data[28:48] original IP header, and data[44:48] is the destination IP address
# data[48:] original TCP/UDP packet, and data[48:50] is the source port

def get_port_from_icmp_packet(data, server):
    port = 0
    ip_hex = b''.join(list(map(lambda x: struct.pack('!B', int(x)), server.split('.')))) 

    if len(data) > 50:
        icmp_type = struct.unpack('!B', data[20:21])[0]
        if icmp_type == 11 and ip_hex == data[44:48]:
            port_hex = data[48 : 50]
            port = int(port_hex.hex(), 16)

    return port


def get_router_ip(icmp_sock, port):
    try:
        while True:
            data, addr = icmp_sock.recvfrom(1508)
            icmp_port = get_port_from_icmp_packet(data, server)
            if port == icmp_port:
                addr = addr[0]
                break
    except:
        addr = '*'
    return addr

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



def dns_request(domain, server, ttl, timeout = 5):
    
    qname = dns.name.from_text(domain)
    q = dns.message.make_query(qname, dns.rdatatype.A).to_wire()
    q = struct.pack('!H', len(q)) + q # prepend 2 bytes packet length


    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_sock.settimeout(1)

    try:
        # tcp handshake
        sock.connect((server, 53))
        port = sock.getsockname()[1]
        
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
        # send DNS-over-TCP query, receive response
        sock.send(q)
        raw_dns_response = sock.recv(1024)

        
        is_timeout = False

        addr = get_router_ip(icmp_sock, port)

        # close socket
        # sock.shutdown(socket.SHUT_RDWR)
        # sock.close()
    
    except socket.timeout:
        raw_dns_response = ''
        is_timeout = True

        addr = get_router_ip(icmp_sock, port)
        
    except:
        raw_dns_response = ''
        is_timeout = False
        addr = '!'

    dns_result = process_raw_dns_response(raw_dns_response, is_timeout)

    dns_result['device'] = addr
    return dns_result



############################################# HTTP Part ##########################################
def process_raw_http_response(raw_http_response, is_timeout):
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
            source = FakeSocket(raw_http_response)
            response = HTTPResponse(source)
            response.begin()
            http_result['text'] = response.read(len(raw_http_response)).decode()
            #http_result['url'] = raw_http_response.url
            http_result['status_code'] = response.status
            http_result['headers'] = dict(response.getheaders())
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


def http_request(domain, server, ttl, timeout = 5):

    request = "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n\r\n" % domain
    request = request.encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_sock.settimeout(1)

    try:
        # tcp handshake
        sock.connect((server, 80))
        port = sock.getsockname()[1]
        #print('send port', port)
    
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
        sock.send(request)
        time.sleep(1)
        

        raw_http_response = recvall(sock)
        is_timeout = False

        addr = get_router_ip(icmp_sock, port)
        
        # close socket
        # sock.shutdown(socket.SHUT_RDWR)
        # sock.close()

    except socket.timeout:
        raw_http_response = b''
        is_timeout = True

        addr = get_router_ip(icmp_sock, port)
    
    except SocketError as e:
        raw_http_response = b''
        is_timeout = False
        addr = '!'

    except Exception as e:
        print(e)
        raw_http_response = b''
        is_timeout = False
        addr = '!'

    
    http_result = process_raw_http_response(raw_http_response, is_timeout)
    http_result['device'] = addr
    return http_result






############################################# SNI Part ##########################################

    
def sni_request(domain, server, ttl, timeout = 5):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_sock.settimeout(1)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS)

    sni_result = dict()
    sni_result['timestamp'] = int(time.time())
    sni_result['cert'] = ''
    sni_result['cert_serial'] = '0'
    sni_result['status'] = 'success'
    sni_result['is_timeout'] = False
    
    try:
        sock.connect((server, 443))
        port = sock.getsockname()[1]
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))

        wrapped_socket = context.wrap_socket(sock, server_hostname = domain)

        addr = get_router_ip(icmp_sock, port)
        
    except socket.timeout:
        sni_result['status'] = 'fail'
        sni_result['is_timeout'] = True
        
        addr = get_router_ip(icmp_sock, port)
    
    except:
        sni_result['status'] = 'fail'
        addr = '!'
    
    else:
        try:
            sni_result['cert'] = ssl.DER_cert_to_PEM_cert(wrapped_socket.getpeercert(True))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, sni_result['cert'])
            sni_result['cert_serial'] = str(x509.get_serial_number())

        except Exception as e:
            print('proxy_sni_error:', e)
            pass


    try:
        wrapped_socket.shutdown(socket.SHUT_RDWR)
        wrapped_socket.close()
    except:
        pass

    sni_result['device'] = addr
    return sni_result





protocol = sys.argv[1]
domain = sys.argv[2]
server = sys.argv[3]
timeout = 2


lower_ttl = 1
upper_ttl = 30
if len(sys.argv) > 5:
    lower_ttl = int(sys.argv[4])
    upper_ttl = int(sys.argv[5])

for ttl in range(lower_ttl, upper_ttl + 1):
    if protocol == 'dns':
        result = dns_request(domain, server, ttl, timeout)
    elif protocol == 'http':
        result = http_request(domain, server, ttl, timeout)
    elif protocol == 'sni':
        result = sni_request(domain, server, ttl, timeout)
        result.pop('cert')
    else:
        print('Wrong protocol!')
        sys.exit(0)
    
    print('ttl = ' + str(ttl), '\t', result)
    if result['is_timeout'] == False:
        break




