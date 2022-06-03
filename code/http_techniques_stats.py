
import json
import os

proxy_path = '../results/proxyrack/'
subdirs = [ f.path for f in os.scandir(proxy_path) if f.is_dir() ]
subdirs.sort()

def http_statistic():
    tech_dic = dict()
    tech_dic['blockpage'] = 0
    tech_dic['timeout'] = 0
    tech_dic['teardown'] = 0
    for subdir in subdirs:
        if subdir.split('/')[-1].startswith('2020'):
            date = subdir.split('/')[-1]
            if date <= '2020-04-15':
                continue
            with open(subdir + '/' + date + '_http_final.txt') as f:
                for entry in f:
                    if entry != '\n':
                        entry_dic = json.loads(entry)
                        for domain in entry_dic['domain']:
                            text_len_list = entry_dic['domain'][domain]['text']
                            is_timeout_list = entry_dic['domain'][domain]['is_timeout']
                            for i in range(len(text_len_list)):
                                text_len = text_len_list[i]
                                is_timeout = is_timeout_list[i]
                                if text_len > 0:
                                    tech_dic['blockpage'] += 1
                                elif is_timeout is True:
                                    tech_dic['timeout'] += 1
                                else:
                                    tech_dic['teardown'] += 1

    return tech_dic

tech_dic = http_statistic()
print(tech_dic)