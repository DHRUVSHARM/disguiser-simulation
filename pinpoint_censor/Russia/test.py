import json

with open('2020-05-21_http_vpn_censorship_json.txt') as f:
	vp_dic = json.loads(f.read().strip())

domains = vp_dic['domain'].keys()

for domain in domains:
	result = vp_dic['domain'][domain][-1]
	if result['text'] != 'http\n':
		print('"' + domain + '"')