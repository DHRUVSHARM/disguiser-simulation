#!/usr/bin/env python3
import socket
import dns.query
import dns.message
import dns.name
import dns.rdatatype
import requests
import ssl
import struct
import OpenSSL
import time
import joblib
import os
import sys
from io import BytesIO
from http.client import HTTPResponse
from socket import error as SocketError


# ---------------------------------------------------------------------
# ICMP helpers
# ---------------------------------------------------------------------
def get_port_from_icmp_packet(pkt: bytes, server_ip: str) -> int:
    """
    Try to recover the *source port* of our original TCP/UDP probe
    from an ICMP Time Exceeded / Dest Unreachable message.

    Layout is:
      [outer IP][ICMP hdr][embedded IP][first 8 bytes of transport]

    We only need the first 8 bytes of the embedded transport header,
    so this should work even when routers send the minimum.
    """
    # need at least outer IP (20) + ICMP (8) + inner IP (20) + 4 bytes = 52
    if len(pkt) < 52:
        return 0

    # outer IP header len
    outer_ihl = (pkt[0] & 0x0F) * 4
    if len(pkt) < outer_ihl + 8:
        return 0

    icmp_type = pkt[outer_ihl]
    if icmp_type not in (3, 11):  # dest unreachable / time exceeded
        return 0

    # embedded IP starts right after ICMP header (8 bytes)
    emb_ip_off = outer_ihl + 8
    if len(pkt) < emb_ip_off + 20:
        return 0

    emb_ip = pkt[emb_ip_off:emb_ip_off + 20]
    emb_ihl = (emb_ip[0] & 0x0F) * 4
    if len(pkt) < emb_ip_off + emb_ihl + 4:
        return 0

    # (optional) check inner dst == server
    inner_dst = emb_ip[16:20]
    # we won't *require* it to match, campus nets sometimes mangle stuff
    # if inner_dst != socket.inet_aton(server_ip):
    #     return 0

    # embedded transport header (tcp/udp) starts here
    emb_trans_off = emb_ip_off + emb_ihl
    emb_trans = pkt[emb_trans_off:emb_trans_off + 4]
    if len(emb_trans) < 4:
        return 0

    sport = struct.unpack("!H", emb_trans[:2])[0]
    return sport
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


def get_router_ip(icmp_sock, expected_sport: int, server: str, max_wait: float = 1.5) -> str:
    """
    Listen for ICMP replies that correspond to our probe.

    - If we find one whose embedded source port == expected_sport -> return that router.
    - If we only see unrelated ICMP (but still for us) -> return the first router we saw.
    - If we see nothing -> return '*'
    - If something blows up -> return '!'
    """
    deadline = time.time() + max_wait
    last_seen = '*'

    try:
        icmp_sock.settimeout(0.3)
    except Exception:
        pass

    while time.time() < deadline:
        try:
            pkt, addr = icmp_sock.recvfrom(4096)
        except socket.timeout:
            break
        except Exception:
            return '!'

        # we got *some* ICMP for us
        last_seen = addr[0]
        print("last seen addr : " , last_seen)

        port_from_icmp = get_port_from_icmp_packet(pkt, server)
        if expected_sport and port_from_icmp == expected_sport:
            # perfect match
            return addr[0]

        if port_from_icmp == 0:
            # router didn’t give us ports, but it *is* the hop
            return addr[0]

        # else: we got an ICMP but port didn’t match → keep listening
        # (somewhere along your campus path they *are* returning full payloads,
        # so this loop can catch that)
    return last_seen


# ---------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------
def extract_ip_address(dns_response):
    ip_list = []
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
    dns_result = {
        'timestamp': int(time.time()), # record time
        'status': 'success', # assume success
        'rcode': -1, # unknown
        'ip_list': [], 
        'is_timeout': is_timeout,
    }

    if not is_timeout:
        # the dns over tcp has a header of 2 bytes before the real payload 
        # this is to indicate the lenfth of the response so we check if that is correct
        try:
            response_length = struct.unpack('!H', raw_dns_response[:2])[0]
            assert len(raw_dns_response[2:]) == response_length
        except Exception:
            dns_result['status'] = 'fail'
        else:
            # get rcode from the dns response
            try:
                dns_response = dns.message.from_wire(raw_dns_response[2:])
                rcode = dns_response.rcode()
                dns_result['rcode'] = rcode
                if rcode == 0:
                    dns_result['ip_list'] = extract_ip_address(dns_response)
            except Exception:
                pass
    else:
        # no reply , timeout so mark simple fail
        dns_result['status'] = 'fail'

    return dns_result


def dns_request(domain, server, ttl, timeout=5):
    """
    domain : domain we want to visit
    server : the resolver 
    """

    # here we build the dns packet using dnspython toolkit
    # converts domain to object of dns name type
    qname = dns.name.from_text(domain)
    # A-record query
    q = dns.message.make_query(qname, dns.rdatatype.A).to_wire()
    q = struct.pack('!H', len(q)) + q  # TCP DNS length prefix for tcp based dns

    # 2 sockets created
    # tcp over ipv4 to send dns query to resolver port 53
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    # listen to raw icmp packet for timeout response
    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_sock.settimeout(3)

    port = None
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
        sock.connect((server, 53))
        port = sock.getsockname()[1]

        sock.send(q)
        raw_dns_response = sock.recv(1024)
        is_timeout = False
        
        # get_router_ip gets the ip of the router that sent the ttl expired
        addr = get_router_ip(icmp_sock, port, server)
    except socket.timeout:
        raw_dns_response = b''
        is_timeout = True
        addr = get_router_ip(icmp_sock, port or 0, server)
    except OSError:
        # THIS is the campus / TTL case: connect() blew up *before* we read ICMP
        raw_dns_response = b''
        is_timeout = True          # ← important: keep sweeping
        addr = get_router_ip(icmp_sock, port or 0, server)
    except Exception:
        raw_dns_response = b''
        is_timeout = True
        addr = get_router_ip(icmp_sock, port or 0, server)
    finally:
        try:
            sock.close()
        except Exception:
            pass
        try:
            icmp_sock.close()
        except Exception:
            pass

    dns_result = process_raw_dns_response(raw_dns_response, is_timeout)
    dns_result['device'] = addr
    return dns_result


# ---------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------
def process_raw_http_response(raw_http_response, is_timeout):
    http_result = {
        'timestamp': int(time.time()),
        'status': 'success',
        'status_code': 0,
        'text': '',
        'headers': {},
        'is_timeout': is_timeout,
    }

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
            http_result['text'] = response.read(len(raw_http_response)).decode(errors='replace')
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


def http_request(domain, server, ttl, timeout=5):
    # here we will try to make a get request to the given domain 
    # simple get request encoded to send over tcp 
    request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode()

    # open tcp socket for sending http  
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    # raw socket that will listen for the timeout ICMP packets 
    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_sock.settimeout(3)

    # since we have not makde the connection we do not know the port yet
    port = None
    try:
        # IP_TTL means we are changing the ttl of the packet 
        # stuff the passed ttl into the packet in binary format 
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
        # use the socket to make connection to server on port 80
        # do handshake
        sock.connect((server, 80))
        # get port on our machine where the socket is if connected
        port = sock.getsockname()[1]

        # send request 
        sock.send(request)
        time.sleep(0.2)
        raw_http_response = recvall(sock)
        is_timeout = False

        # mark as not timeout and try to get ip
        addr = get_router_ip(icmp_sock, port, server)
    except socket.timeout:
        raw_http_response = b''
        is_timeout = True
        addr = get_router_ip(icmp_sock, port or 0, server)
    except OSError:
        raw_http_response = b''
        is_timeout = True
        addr = get_router_ip(icmp_sock, port or 0, server)
    except Exception:
        raw_http_response = b''
        is_timeout = True
        addr = get_router_ip(icmp_sock, port or 0, server)
    finally:
        try:
            sock.close()
        except Exception:
            pass
        try:
            icmp_sock.close()
        except Exception:
            pass

    http_result = process_raw_http_response(raw_http_response, is_timeout)
    http_result['device'] = addr
    return http_result


# ---------------------------------------------------------------------
# SNI / TLS
# ---------------------------------------------------------------------
def sni_request(domain, server, ttl, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_sock.settimeout(3)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS)

    sni_result = {
        'timestamp': int(time.time()),
        'cert': '',
        'cert_serial': '0',
        'status': 'success',
        'is_timeout': False
    }
    wrapped_socket = None
    port = None
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
        sock.connect((server, 443))
        port = sock.getsockname()[1]

        wrapped_socket = context.wrap_socket(sock, server_hostname=domain)
        addr = get_router_ip(icmp_sock, port, server)
    except socket.timeout:
        sni_result['status'] = 'fail'
        sni_result['is_timeout'] = True
        addr = get_router_ip(icmp_sock, port or 0, server)
    except OSError:
        sni_result['status'] = 'fail'
        sni_result['is_timeout'] = True
        addr = get_router_ip(icmp_sock, port or 0, server)
    except Exception:
        sni_result['status'] = 'fail'
        addr = get_router_ip(icmp_sock, port or 0, server)
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
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
        try:
            icmp_sock.close()
        except Exception:
            pass

    sni_result['device'] = addr
    return sni_result


# ---------------------------------------------------------------------
# main sweep
# ---------------------------------------------------------------------
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
    print(f"=== TTL sweep {domain} via {server} ({protocol}) ===")

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
        result.pop('cert', None)
    else:
        print('Wrong protocol!')
        sys.exit(1)

    print('ttl =', ttl, '\t', result)

    # IMPORTANT: only break when we actually reached the target (no timeout AND success)
    if result['is_timeout'] is False and result.get('status') == 'success' and result.get('ip_list'):
        break

