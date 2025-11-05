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


"""
for reference we can see these expected responses 

| Event                          | What it means                                    | Example                            |
| ------------------------------ | ------------------------------------------------ | ---------------------------------- |
| ✅ **Success**                  | Packet reached destination normally.             | HTTP 200 OK, DNS A record returned |
| ⚠️ **Timeout**                 | No response — could be dropped.                  | Packet never echoed or filtered    |
| ❌ **RST (TCP Reset)**          | Some device injected a TCP Reset (active block). | Common in China’s GFW              |
| ❌ **NXDOMAIN / altered DNS**   | DNS reply is forged or incorrect.                | Poisoned DNS cache                 |
| ❌ **TLS alert / invalid cert** | HTTPS-level interference.                        | Man-in-the-middle block            |

"""

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


def get_router_ip(icmp_sock, port, max_wait=3.0):
    end = time.time() + max_wait
    last = '*'
    while time.time() < end:
        try:
            data, addr = icmp_sock.recvfrom(1508)
            icmp_port = get_port_from_icmp_packet(data, server)
            # record first seen hop; prefer a matching-port hit
            last = addr[0]
            if port == icmp_port:
                return addr[0]
        except socket.timeout:
            break
        except Exception:
            break
    return last


############################################# DNS Part ##########################################
def extract_ip_address(dns_response):
    ip_list = list()
    for rrset in dns_response.answer:
        if rrset.rdtype == dns.rdatatype.A:
            for rr in rrset:
                ip_list.append(rr.address)
    return ip_list



def process_raw_dns_response(raw_dns_response, is_timeout):
    """
    | RCODE name | Numeric | Meaning                                                |
    | ---------- | ------- | ------------------------------------------------------ |
    | `NOERROR`  | 0       | Domain exists – A record(s) returned                   |
    | `NXDOMAIN` | 3       | “Non-existent domain” – resolver says it doesn’t exist |
    | `SERVFAIL` | 2       | Server failure (resolver internal error)               |
    | `REFUSED`  | 5       | Resolver refused to answer                             |
    | timeout    | —       | No reply at all → possible drop/block                  |

    """
    dns_result = dict()
    dns_result['timestamp'] = int(time.time()) # record time
    dns_result['status'] = 'success' # assume success
    dns_result['rcode'] = -1 # unknown
    dns_result['ip_list'] = list() 
    dns_result['is_timeout'] = is_timeout

    if not is_timeout:
        # the dns over tcp has a header of 2 bytes before the real payload 
        # this is to indicate the lenfth of the response so we check if that is correct
        try:
            response_length = struct.unpack('!H', raw_dns_response[:2])[0]
            assert len(raw_dns_response[2:]) == response_length
        
        except:
            # packet parse failure
            dns_result['status'] = 'fail'
        
        else:
            # get rcode from the dns response
            try:
                dns_response = dns.message.from_wire(raw_dns_response[2:])
                rcode = dns_response.rcode()
                dns_result['rcode'] = rcode
                
                # rcode 0 means we have a valid ip returned , refer above for all codes
                # NOTE : the stop condition of the probe is when we reach here or when all ttl probes are finsihed 
                if rcode == 0:
                    ip_list = extract_ip_address(dns_response)
                    dns_result['ip_list'] = ip_list # single domain can map to multiple ips hence we use a list
            except:
                pass
    else:
        # no reply , timeout so mark simple fail
        dns_result['status'] = 'fail'

    
    return dns_result


def dns_request(domain, server, ttl, timeout = 5):
    """
    domain : domain we want to visit
    server : the resolver 
    """

    # here we build the dns packet using dnspython toolkit
    # converts domain to object of dns name type
    qname = dns.name.from_text(domain)
    # A-record query
    q = dns.message.make_query(qname, dns.rdatatype.A).to_wire()
    q = struct.pack('!H', len(q)) + q  # prepend 2 bytes packet length for tcp based dns

    # 2 sockets created
    # tcp over ipv4 to send dns query to resolver port 53
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    # listen to raw icmp packet for timeout response
    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_sock.settimeout(3)  # was 1s

    port = None
    try:
        # set TTL **before** connect
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
        sock.connect((server, 53))
        port = sock.getsockname()[1]

        sock.send(q)
        raw_dns_response = sock.recv(1024)
        is_timeout = False
        
        # get_router_ip gets the ip of the router that sent the ttl expired
        addr = get_router_ip(icmp_sock, port)
    except socket.timeout:
        raw_dns_response = b''
        is_timeout = True
        addr = get_router_ip(icmp_sock, port) if port is not None else '*'
    except Exception:
        raw_dns_response = b''
        is_timeout = False
        addr = '!'
    finally:
        try: sock.close()
        except: pass
        try: icmp_sock.close()
        except: pass

    dns_result = process_raw_dns_response(raw_dns_response, is_timeout)
    dns_result['device'] = addr
    return dns_result


############################################# HTTP Part ##########################################
def process_raw_http_response(raw_http_response, is_timeout):
    http_result = dict()
    http_result['timestamp'] = int(time.time())
    http_result['status'] = 'success'
    http_result['status_code'] = 0
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
    # here we will try to make a get request to the given domain 
    request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_sock.settimeout(3)

    port = None
    try:
        # set TTL **before** connect
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
        sock.connect((server, 80))
        port = sock.getsockname()[1]

        sock.send(request)
        time.sleep(0.2)  # shorter; we just need initial response
        raw_http_response = recvall(sock)
        is_timeout = False

        addr = get_router_ip(icmp_sock, port)
    except socket.timeout:
        raw_http_response = b''
        is_timeout = True
        addr = get_router_ip(icmp_sock, port) if port is not None else '*'
    except SocketError:
        raw_http_response = b''
        is_timeout = False
        addr = '!'
    except Exception:
        raw_http_response = b''
        is_timeout = False
        addr = '!'
    finally:
        try: sock.close()
        except: pass
        try: icmp_sock.close()
        except: pass

    http_result = process_raw_http_response(raw_http_response, is_timeout)
    http_result['device'] = addr
    return http_result





############################################# SNI Part ##########################################
def sni_request(domain, server, ttl, timeout = 5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_sock.settimeout(3)

    # You can keep PROTOCOL_TLS (warning is harmless), or use PROTOCOL_TLS_CLIENT on newer OpenSSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)

    sni_result = {'timestamp': int(time.time()), 'cert': '', 'cert_serial': '0',
                  'status': 'success', 'is_timeout': False}
    wrapped_socket = None
    port = None
    try:
        # set TTL **before** connect
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
        sock.connect((server, 443))
        port = sock.getsockname()[1]

        wrapped_socket = context.wrap_socket(sock, server_hostname=domain)
        addr = get_router_ip(icmp_sock, port)
    except socket.timeout:
        sni_result['status'] = 'fail'
        sni_result['is_timeout'] = True
        addr = get_router_ip(icmp_sock, port) if port is not None else '*'
    except Exception:
        sni_result['status'] = 'fail'
        addr = '!'
    else:
        try:
            sni_result['cert'] = ssl.DER_cert_to_PEM_cert(wrapped_socket.getpeercert(True))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, sni_result['cert'])
            sni_result['cert_serial'] = str(x509.get_serial_number())
        except Exception:
            pass
    finally:
        try:
            if wrapped_socket:
                wrapped_socket.shutdown(socket.SHUT_RDWR)
                wrapped_socket.close()
        except: pass
        try: sock.close()
        except: pass
        try: icmp_sock.close()
        except: pass

    sni_result['device'] = addr
    return sni_result





protocol = sys.argv[1]
domain = sys.argv[2]
server = sys.argv[3]
timeout = 2


# main driver here we have 3 different functions for three protocols

# default ttl
lower_ttl = 1
upper_ttl = 60


if len(sys.argv) > 5:
    lower_ttl = int(sys.argv[4])
    upper_ttl = int(sys.argv[5])

for ttl in range(lower_ttl, upper_ttl + 1):

    if protocol == 'dns':
        # NOTE : SUMMARY IS MAKE DNS QUERY PACKET for facebook.com destined to the DNS resolver (8.8.8.8 , FOR EX) (which will be our resolver) 
        # QUICK NOTE : example usage would be :
        #  python pinpoint_censor.py dns facebook.com 8.8.8.8 1 20 
        result = dns_request(domain, server, ttl, timeout)
        # querying using http protocol 
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




