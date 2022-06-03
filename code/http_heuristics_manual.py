import json
import os
import sys
import numpy as np 
import pandas as pd 
from matplotlib import pyplot as plt 
from sklearn.cluster import KMeans       
import webbrowser
import random

proxy_path = '../results/proxyrack/'
subdirs = [ f.path for f in os.scandir(proxy_path) if f.is_dir() ]
subdirs.sort()


def get_webpage_length():
    country_dic = dict()
    for subdir in subdirs:
        if subdir.split('/')[-1].startswith('2020'):
            with open(subdir + '/' + 'http_manual_case.txt') as f:
                vps = json.loads(f.read().strip())
                for vp in vps:
                    country = vps[vp]['country']
                    if country not in country_dic:
                        country_dic[country] = dict()
                        country_dic[country]['country'] = country
                        country_dic[country]['length'] = list()
                    for domain in vps[vp]['domain']:
                        length = len(vps[vp]['domain'][domain]['text'])
                        country_dic[country]['length'].append(length)
    return country_dic

def get_webpage_by_length(country, webpage_length):
    webpage_info_list = list()
    for subdir in subdirs:
        if subdir.split('/')[-1].startswith('2020'):
            start_date = subdir.split('/')[-1]
            with open(subdir + '/' + 'http_manual_case.txt') as f:
                vps = json.loads(f.read().strip())
                for vp in vps:
                    if country != vps[vp]['country']:
                        continue
                    for domain in vps[vp]['domain']:
                        length = len(vps[vp]['domain'][domain]['text'])
                        if length in webpage_length:
                            entry = tuple((start_date, country, vp, domain, vps[vp]['domain'][domain]['text'], vps[vp]['domain'][domain]['headers']))
                            webpage_info_list.append(entry)
    return webpage_info_list



def get_webpage_by_ip(ip):
    webpage_info_list = list()
    for subdir in subdirs:
        if subdir.split('/')[-1].startswith('2020'):
            start_date = subdir.split('/')[-1]
            with open(subdir + '/' + 'http_manual_case.txt') as f:
                vps = json.loads(f.read().strip())
                for vp in vps:
                    if vp == ip:
                        country = vps[vp]['country']
                        for domain in vps[vp]['domain']:
                            #length = len(vps[vp]['domain'][domain]['text'])
                            entry = tuple((start_date, country, vp, domain, vps[vp]['domain'][domain]['text'], vps[vp]['domain'][domain]['headers']))
                            webpage_info_list.append(entry)
    return webpage_info_list


def plot_elbow(web_page_length):
    wcss = []
    for i in range(1, 11):
        kmeans = KMeans(n_clusters=i, init='k-means++', max_iter=300, n_init=10, random_state=0)
        kmeans.fit(np.array(web_page_length).reshape(-1, 1))
        wcss.append(kmeans.inertia_)
    plt.plot(range(1, 11), wcss)
    plt.title('Elbow Method')
    plt.xlabel('Number of clusters')
    plt.ylabel('WCSS')
    plt.show()


def open_webpage(country, cluster, web_page_length):
    kmeans = KMeans(n_clusters=cluster, init='k-means++', max_iter=300, n_init=10, random_state=0)
    pred_y = kmeans.fit_predict(np.array(web_page_length).reshape(-1, 1))

    label = list(pred_y)
    cluster_dic = dict()
    for i in range(len(web_page_length)):
        cluster = label[i]
        if cluster not in cluster_dic:
            cluster_dic[cluster] = list()
        cluster_dic[cluster].append(web_page_length[i])

    min_group = 0
    for key in cluster_dic:
        print(key, len(cluster_dic[key]))
        if len(cluster_dic[key]) < len(cluster_dic[min_group]):
            min_group = key 

    webpage_length = cluster_dic[min_group]
    webpage_info_list = get_webpage_by_length(country, webpage_length)
    random.shuffle(webpage_info_list)

    for webpage_info in webpage_info_list[:10]:
        start_date, country, vp, domain, webpage, headers = webpage_info

        path = os.path.abspath('temp.html') 
        url = 'file://' + path
        with open(path, 'w') as f: 
            f.write(domain + '\n' + webpage)
        webbrowser.open(url)
        print(start_date, country, vp, len(webpage), domain, headers)

    # for webpage_info in webpage_info_list:
    #     start_date, country, vp, domain, webpage, headers = webpage_info
    #     if len(webpage) > 1000 or len(webpage) < 600:
    #         path = os.path.abspath('temp.html') 
    #         url = 'file://' + path
    #         with open(path, 'w') as f: 
    #             f.write(domain + '\n' + webpage)
    #         webbrowser.open(url)
    #         print(start_date, country, vp, len(webpage), domain, headers)




webpage_length_dic = get_webpage_length()
with open('test.txt', 'w') as f:
    for country in webpage_length_dic:
        f.write(json.dumps(webpage_length_dic[country]) + '\n\n')

# command = sys.argv[1]
# country = sys.argv[2]
# #country = ' '.join(sys.argv[2:-1])
# print(country)


# if command == 'elbow':
#     web_page_length = webpage_length_dic[country]['length']
#     plot_elbow(web_page_length)
# elif command == 'open':
#     cluster = int(sys.argv[-1])
#     web_page_length = webpage_length_dic[country]['length']
#     open_webpage(country, cluster, web_page_length)


