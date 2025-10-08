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

## Intro to Network Traffic Analysis
* cyber kill chain: seven-step methodology developed by Lockheed Martin, outlining the steps an attacker takes to infiltrate a network or system
* MITRE ATT&CK matrix: comprehensive knowledge base of attack techniques and tactics based on real-world observations
* SIEM:
  * EventID 5140: Server Message Block [SMB] Share access
  * EventID 4688: Process Execution
### ELOs
#### Understand methods for identifying adversarial Tactics, Techniques, and Procedures (TTP) from MITRE
* monitoring for suspicious network traffic that could be indicative of probing for email addresses and/or usernames, such as large/iterative quantities of authentication requests originating from a single source
* using malware forensics, up-to-date antivirus software, or a known malware database
#### Understand the common Command and Control (C2) beaconing methods and attributes
* one concept is using the compromised hosts to communicate back to the adversary
#### Understand obfuscation techniques
* an adversary applies jitter, or randomness, to the beacon timing to make it more difficult to track (there is no longer regular intervals for a team to monitor)
* Data Masking: alters sensitive fields within the traffic (such as usernames, passwords, or personal identifiers) by replacing them with fictitious but realistic values, ensuring the underlying structure is preserved while hiding the true information.
* Data Encoding: transforms data into another format, such as Base64 or hexadecimal, which conceals the original content from direct readability while still being REVERSIBLE
#### Understand Address Resolution Protocol (ARP) spoofing
* form of MitM attack that allows adversaries to intercept communications between network devices by sending poisoned ARP responses pretending to be one of the authentic devices and beginning to intercept credentials intended for a different system
#### Understand different types of attack methods, including Man-in-the-Middle (MitM) or Person-in-the-Middle (PitM) attacks
* MitM: arp spoofing
* adversary eavesdrops on a conversation between two hosts
* execute code to capture credentials for privilege escalation
#### Understand data exfiltration techniques
  
#### Understand link and timeline analysis





