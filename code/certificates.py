import json
import os
import OpenSSL

proxy_path = '../results/proxyrack/'
subdirs = [ f.path for f in os.scandir(proxy_path) if f.is_dir() ]
subdirs.sort()

with open('../results/proxyrack/proxyrack_certs.json') as f:
    cert_dic = json.loads(f.read().strip())

def get_certificate_info():
    cert_info_list = list()
    for subdir in subdirs:
        if subdir.split('/')[-1].startswith('20'):
            date = subdir.split('/')[-1]
            with open(subdir + '/' + date + '_sni_final.txt') as f:
                for entry in f:
                    if entry != '\n':
                        entry_dic = json.loads(entry)
                        country = entry_dic['country']
                        domain_dic = entry_dic['domain']
                        for domain in domain_dic:
                            for i, cert_serial in enumerate(domain_dic[domain]['cert_serial']):
                                if cert_serial != "0":
                                    cert_info_list.append(tuple((subdir.split('/')[-1], cert_serial, domain, country, domain_dic[domain]['ip'][i], cert_dic[cert_serial])))
    return cert_info_list

checked_cert = []
total_ips = set()
total_countries = set()
total_domains = set()
cert_info_list = get_certificate_info()
for cert_info in cert_info_list:
    f, cert_serial, domain, country, ip, pem = cert_info
    # if cert_serial in checked_cert:
    #     continue
    if cert_serial != '207438071331994644551965636229385064171':
        continue
    checked_cert.append(cert_serial)
    try:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
        subject = cert.get_subject()
        issuer = cert.get_issuer()
        
        total_ips.add(ip)
        total_countries.add(country)
        total_domains.add(domain)
    except:
        print(cert_info)
        exit(0)
    print(f)
    print(domain, country)
    # print(ip)
    print(country)
    print(cert_serial)
    print(subject.get_components())
    print(issuer.get_components())
    # print()

print('ips:', total_ips)
print('country:', len(total_countries))
print('domain', len(total_domains))