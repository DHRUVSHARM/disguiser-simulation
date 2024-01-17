## Checklist of Best Practice for Deploying Secure and Reliable Cloud Instances as Backend Servers

To deploy Disguiser, one or more backend control is required to provide static content for accurately and automatically identifying the potential censorship activites. In our experiment framework, we launch such servers on public cloud platforms (Amazon AWS, Microsoft Azure, and Google Cloud Platform). Deploying such backend server may also introduce weaknesses/risks to the system and requires special attentions. Here we complie a best practice list, produced by the auditing process conducted by our project's funding agency, the  [Open Technology Fund](https://www.opentech.fund/) (OTF) who funded this pro, for illustrating the potential issues in our original configuration and the suggestions for securely deploying the backend control server on cloud infrastructures. The detail of the framework and a comprehensive measurement study on global censorship can be found in our ACM SIGMETRICS’22 **[paper](https://e2ecensor.github.io/assets/pdf/sigmetrics22.pdf)**.

#### AWS Leaks via Unencrypted EBS Volumes & Snapshots 

> AWS volumes across all used regions were found to be stored without prior encryption at rest. In case sensitive data is stored on these unencrypted volumes, this may not only leak data, but also violate compliance with multiple frameworks. It should be noted that, when the encryption option is disabled, potential flaws in the AWS implementation might allow unauthorized attackers to access the volume. This might occur through an AWS access control flaw, as well as physical attacks where hard/SSD drives are replaced in the data center. Hence, encryption provides an additional security layer for such scenarios and minimizes potential unintentional data disclosure. 

**Recommendations**: It is recommended to enable encryption, ideally by default, for all newly created volumes.

#### AWS Weaknesses in Vuln Management Processes

> During the configuration audit of the AWS production account, it was discovered that multiple AWS security-relevant services are not configured correctly. Failure to leverage these services can leave the infrastructure open to attacks due to insufficient hardening.

**Recommendations**: It is recommended to implement as many AWS Security related services as possible. This should include tools like Security Hub13, Config14, Guard Duty15, Macie16 and Inspector17. After this, the infrastructure team should ensure that all relevant services, and equivalent products, are enabled for the whole environment in all used regions. Furthermore, any reported issues should be regularly reviewed and remediated. This should ideally be accomplished by leveraging an infrastructure-as-code approach such as Terraform18, which would significantly simplify applying the same settings across all AWS accounts. Please note that cloud-native security tools are not perfect, however they provide a solid baseline for each environment. Special consideration should be given to Security Hub and Config, as they allow to streamline and discover common misconfigurations.

#### Possible AWS Takeover via IAM Root Account Use

> It was found that the analyzed environment uses only the main AWS root account for actions that could be performed with more restricted accounts. AWS root accounts are the main and most privileged accounts in the AWS environment. Using a root account, either via the API or interactively via the AWS Web Console, unnecessarily increases the likelihood of unauthorized access. In certain cases, this may also weaken the security policy, as commonly MFA is enabled only for Web Console access and is disabled for the API.

**Recommendations**: It is recommended to protect AWS root accounts. This should be accomplished utilizing a strong password and MFA, ideally a hardware-based MFA mechanism. These accounts should only be used occasionally, instead personal accounts for daily operations19 should be created and configured to only have the absolute minimum permissions necessary to perform their function.

#### Insufficient AWS Logging & Monitoring

> It was found that AWS CloudTrail is not enabled for all regions. This tool records all activities in an AWS account as events. Without adequate logging, it may be impossible to monitor malicious activities, or use integrated tools that analyze CloudTrail for anomalies, all of which may be critical in the event of a security breach.


**Recommendations**: It is recommended to enable CloudTrail for all regions, and ensure logs are automatically archived in encrypted S3 buckets that belong to a separate AWS account. By default CloudTrail stores only the last 90 days of activity in AWS, thus archiving is crucial for potential forensic investigations in case of a breach. Additionally, logs from virtual machines should be considered to be integrated with a centralized logging system for better coverage.

In general, all logging and monitoring settings should be adjusted depending on the threat model, compliance requirements and volume of generated data. Excessively verbose logs may increase the overall infrastructure cost significantly, however, lack of appropriate logging and monitoring decreases the chances of successful threat detection and analysis in case of a breach. It is advised to review and improve the logging and monitoring configuration in the context of a potential incident response case rather than just regular daily operations of the infrastructure.


#### Unrestricted Inbound Traffic on GCP

> It was discovered that the Google Cloud Platform (GCP) firewall rules fail to restrict access to virtual machines. This weakness appears to be due to VPC usage, which creates insecure firewall rules by default. This implies that services launched by administrators, which listen on a network interface, will be immediately exposed to attacks from the Internet. For example, malicious adversaries that constantly scan the Internet for easy targets might be able to exploit misconfigurations in the exposed services.

**Recommendations**: It is recommended to remove default VPC as multiple insecure firewall rules are defined automatically23 when a default VPC is in use. It is further suggested to restrict traffic to ports that have to be exposed to the Internet. In case of management access to the virtual machines, either SSH should be open to limited IP addresses, or OS Login with multi-factor authentication should be used. For additional mitigation guidance, please see the CIS Google Cloud Computing Platform Benchmark.


















