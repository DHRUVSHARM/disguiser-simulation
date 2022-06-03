import json




with open('../materials/domain_webpage/valid_domains.txt') as f:
    valid_domains = f.read().strip().split()
valid_domain_dic = dict()
for domain in valid_domains:
    valid_domain_dic[domain] = True

domain_category_dic = dict()
with open('../materials/domain_category/domain_category_dict.txt') as f:
    for entry in f:
        components = entry.strip().split()
        domain = components[0]
        if domain in valid_domain_dic:
            category = ' '.join(components[1:])
            domain_category_dic[domain] = category

domain_set = set()
with open('../results/proxyrack/final/overall_statistic.txt') as f:
    for entry in f:
        if entry != '\n':
            entry_dic = json.loads(entry)
            for domain in entry_dic['domain']:
                domain_set.add(domain)
category = dict()
for domain in domain_category_dic:
    category[domain_category_dic[domain]] = 0

for domain in domain_set:
    category[domain_category_dic[domain]] += 1

for key in category:
    print(key, category[key])