import os
import json
import statistics

proxy_path = '../results/proxyrack/'
subdirs = [ f.path for f in os.scandir(proxy_path) if f.is_dir() ]
subdirs.sort()

ripe_atlas_path = '../results/ripe_atlas/ripe_atlas_results_updated.txt'

def get_ripe_atlas_vantage_points():
    vps = list()
    with open(ripe_atlas_path) as f:
        for entry in f:
            entry_dic = json.loads(entry)
            proxy = entry_dic['probe']
            if proxy not in vps:
                vps.append(proxy)
    return vps



def get_proxy_vantage_points(protocol):
    vps = list()
    for subdir in subdirs:
        if subdir.split('/')[-1].startswith('20'):
            print(subdir)
            date = subdir.split('/')[-1]
            with open(subdir + '/' + date + '_' + protocol + '_proxyrack_censorship_json.txt') as f:
                for entry in f:
                    entry_dic = json.loads(entry)
                    proxy = entry_dic['proxy']
                    if proxy not in vps:
                        vps.append(proxy)
    return vps



# ripe_atlas_vps = get_ripe_atlas_vantage_points()
# country_dic = dict()
# asn_dic = dict()
# for vp in ripe_atlas_vps:
#     country = vp['country']
#     asn = vp['as'].split()[0]
#     country_dic[country] = country_dic.get(country, 0) + 1
#     asn_dic[asn] = asn_dic.get(asn, 0) + 1

# number_of_vps = len(ripe_atlas_vps)
# number_of_countries = len(country_dic)
# medain_of_countries = statistics.median(country_dic.values())
# number_of_ases = len(asn_dic)
# medain_of_ases = statistics.median(asn_dic.values())

# print('number_of_vps', number_of_vps)
# print('number_of_countries', number_of_countries)
# print('medain_of_countries', medain_of_countries)
# print('number_of_ases', number_of_ases)
# print('medain_of_ases', medain_of_ases)
# print()

total_country = list()
total_vantage_point = list()

protocols = ['dns', 'http', 'sni']
for protocol in protocols:
    vps = get_proxy_vantage_points(protocol)
    country_dic = dict()
    asn_dic = dict()

    for vp in vps:
        country = vp['country']
        country_dic[country] = country_dic.get(country, 0) + 1
        try:
            asn = vp['as'].split()[0]
            asn_dic[asn] = asn_dic.get(asn, 0) + 1
        except:
            print(vp)
        
    number_of_vps = len(vps)
    number_of_countries = len(country_dic)
    medain_of_countries = statistics.median(country_dic.values())
    number_of_ases = len(asn_dic)
    medain_of_ases = statistics.median(asn_dic.values())

    print(protocol) 
    print('number_of_vps', number_of_vps)
    print('number_of_countries', number_of_countries)
    print('medain_of_countries', medain_of_countries)
    print('number_of_ases', number_of_ases)
    print('medain_of_ases', medain_of_ases)
    print()
    total_vantage_point += list(map(lambda vp: vp['query'], vps))
    total_country += list(country_dic.keys())

total_vantage_point = list(set(total_vantage_point))
total_country = list(set(total_country))
print('total_vantage_point:', len(total_vantage_point))
print('total_country:', len(total_country))
