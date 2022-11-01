## Disguiser: End-to-End Framework for Measuring Censorship with Ground Truth

#### High-level Ideas

The detection of Internet censorship usually requires heavy manual inspection due to the lack of ground truth, resulting in the difficulty of identifying false positives (i.e., misclassified censorship) and false negatives (i.e., undetected censorship). The difficulty stems from the fact that without ground truth, in many cases it is unlikely to automatically distinguish the legitimate responses and the responses manipulated by censorship. Existing studies tackled such issues by retrieving and comparing distributed responses, but such an approach usually requires manual inspection, causing the analysis unscalable and inefficient.

The project aims to explore, develop, and deploy a framework that enables end-to-end measurement for accurately and automatically investigating global Internet censorship practices. The key idea is to provide a static payload as ground truth, which can be used to indicate the occurrence of censorship when the static payload has been altered by network devices. Moreover, the deployed end-to-end framework can facilitate extended measurements for investigating more aspects of Internet censorship, for example, pinpointing censor devices’ locations and exploring their policies and deployment.

The detail of the framework and a comprehensive measurement study on global censorship can be found in our ACM SIGMETRICS’22 **[paper](https://e2ecensor.github.io/assets/pdf/sigmetrics22.pdf)**.

#### Notes for Data and Code 

Relevant Dataset:
- Alexa List: Amazon's Alexa Top-site list. In our experiments, we use Alexa’s top 1,000 domains as the popular domain list.
- Citizen Lab List: We also test the sensitive domains by using the test lists provided by [Citizen Lab](https://citizenlab.ca/). The Citizen Lab offers two types of test lists, a global test list and a country-specific test list for certain counties. We compile the country-specific test list with the popular list and global test list to form the domain list for each country. The up-to-date list can be accessed at https://github.com/citizenlab/test-lists/.

Experiments Data:
- The datasets that are collected by our framework (and those used in the aforementioned paper) can be obtained **[here](https://drive.google.com/drive/u/1/folders/106F_7gkKO-zRqpdyOokGT_Gr-wonRfnk)**.

Vantage Points:
- SOCKS proxies: We use residential proxies to issue TCP-based DNS queries and HTTP/HTTPS queries through the SOCKS proxies. In our study, we sign-up [ProxyRack](https://www.proxyrack.com/).
- RIPE Atlas: We use [RIPE Atlas](https://atlas.ripe.net/) to conduct UDP-based DNS tests to complement the results of TCP-based measurement from SOCKS proxies.
- VPN: We use VPN vantage points to conduct the application traceroute to investigate the deployment of censors. There are two additional requirements for a VPN server to carry out such an experiment: (1) the VPN server and its default gateway should not alter the TTL values of our packets so that the
intermediate routers can process the packets properly according to the TTL values we set and (2) the VPN server must be physically located in the country as advertised. 

Backend Server Setup:
- Backend Server Setup

Code repository:
- build\_domain\_category.py: 
- build\_domain\_webpage.py: this code help extract the title and landing page of the sensitive domains in testing list and store the output in separte two files. 
- category_percentage.py:
- certificates.py:
- dns_heuristics.py:
- filtered_request.py:
- http_heuristics.py:
- pinpoint_censor.py: perform application traceroute on HTTP proctocol which pinpoints the censor's location on specific router.
- proxy_request.py: define the data format of responses that collecting from censorship measurements on DNS, HTTP, HTTPS protocol.  
- proxyrack.py: this code for conducting HTTP experiments on distrubuted residential proxy provided by proxyrack platform, and receving either static payload from the controlled server or censorship. 
- proxyrack_client.py: define rules/thresholds to obtain as many vantage points as possible from the proxy platforms we used in this experiment.
- proxyrack_process.py: 
- reproduce-data.py:
- ripe\_atlas\_client.py:
- ripe\_atlas\_process.py:
- setup.py: to store confidential information for other files. 
- statistic.py:
- vantage_points.py:
- vpn_client.py:
