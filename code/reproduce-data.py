import json
import sys

raw_path = '../results/proxyrack/raw/'
cleaned_path = '../results/proxyrack/'


with open(raw_path + 'used_ips.json') as f:
    used_ip = json.loads(f.read())

start_date = sys.argv[1]
for protocol in ['dns', 'http', 'sni']:
    input_file = raw_path + start_date + '/' + start_date + '_' + protocol + '_proxyrack_censorship_json.txt'
    output_file = cleaned_path + start_date + '/' + start_date + '_' + protocol + '_proxyrack_censorship_json.txt'
    with open(output_file, 'w') as output_f:
         with open(input_file) as input_f:
             for entry in input_f:
                 entry_dic = json.loads(entry.strip())
                 proxy = entry_dic['proxy']
                 ip = proxy['query']
                 if not ip in used_ip[protocol]:
                     used_ip[protocol].append(ip)
                     output_f.write(entry)

with open(raw_path + 'used_ips.json', 'w') as f:
    f.write(json.dumps(used_ip))