## Disguiser: End-to-End Framework for Measuring Censorship with Ground Truth

#### High-level Ideas

The detection of Internet censorship usually requires heavy manual inspection due to the lack of ground truth, resulting in the difficulty of identifying false positives (i.e., misclassified censorship) and false negatives (i.e., undetected censorship). The difficulty stems from the fact that without ground truth, in many cases it is unlikely to automatically distinguish the legitimate responses and the responses manipulated by censorship. Existing studies tackled such issues by retrieving and comparing distributed responses, but such an approach usually requires manual inspection, causing the analysis unscalable and inefficient.

The project aims to explore, develop, and deploy a framework that enables end-to-end measurement for accurately and automatically investigating global Internet censorship practices. The key idea is to provide a static payload as ground truth, which can be used to indicate the occurrence of censorship when the static payload has been altered by network devices. Moreover, the deployed end-to-end framework can facilitate extended measurements for investigating more aspects of Internet censorship, for example, pinpointing censor devices’ locations and exploring their policies and deployment.

The detail of the framework and a comprehensive measurement study on global censorship can be found in our ACM SIGMETRICS’22 paper (https://e2ecensor.github.io/assets/pdf/sigmetrics22.pdf).

#### Notes for Data and Code 

Relevant Dataset:
- Alexa List:
- Citizen Lab List:

Vantage Points:
- SOCKS proxies:
- RIPE Atlas:
- VPN:

Code repository:
- build\_domain\_category.py:
- build\_domain\_webpage.py:
- category_percentage.py:
- certificates.py:
- dns_heuristics.py:
- filtered_request.py:
- http_heuristics.py:
- pinpoint_censor.py:
- proxy_request.py:
- proxyrack.py:
- proxyrack_client.py:
- proxyrack_process.py:
- reproduce-data.py:
- ripe\_atlas\_client.py:
- ripe\_atlas\_process.py:
- setup.py:
- statistic.py:
- vantage_points.py:
- vpn_client.py:
