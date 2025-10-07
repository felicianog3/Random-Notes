## Intro to mapping/asset inventory
### ELOs
#### Examine security concepts
* it's important to identify "rogue systems": they are different IoT devices that are connected to the network without having proper security protocols in place
* how do you detect rogue systems:
* network scans
* port scans
* intrusion detection systems
* Endpoint security solutions: antivirus, firewalls
* AD analysis: anallysing an organization's network documentation
* banner grabbing
* Passive: only captures information being sent to the system, without sending any requests to the victim system, therefore, a low risk of detection
* Active: packets are sent to the target to analyze the response data. This involves the establishment of a connection between the host and the target client

## Intro to MITRE ATT&CK
### ELOs
#### Explain how registry keys are used from an adversary perspective
* persistence in a target device can be achieved by altering registry keys such as HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
#### Discuss the importance of footprinting and fingerprinting
* identify the function of network services
* mapping an organization's network; finding key points and personnel of interest
#### Discuss the importance of probing and enumeration
* connecting to many netowork ports and IP address to see their response
#### Discuss adversary offensive actions in relation to the MITRE ATT&CK framework

#### Describe how an adversary removes evidence
* obfuscating code, using rootkits, or employing encryption to conceal malicious activities
#### Describe data mining
* Identifying servers containing databases and stealing the data directly
#### Explain security measures when given an adversary TTP

#### Explain security controls to detect and inhibit known adversary TTP
