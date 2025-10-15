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
* System Monitor
  * EventID 17 & 18: pipe creations, searching for administrator share access
 Named Pipes
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
 * accomplished across existing C2 channels, cloud providers, online storage providers, or even through removable media if adversaries have physical access
 * extract small bits at a time to avoid detection
#### Understand link and timeline analysis
* trace the attacker's activities back to the source of the intrusion
* provides insight into adversary activities by chronologically ordering events
* Link Analysis: statistics and relationships within a given dataset





## Intro to Networking Concepts
* Switch Spoofing: attacker negotiates a trunk link to a legitimate switch to intercept traffic destined for another VLAN
* Spanning Tree Protocol (STP): works at closing off redundant paths until needed, which eliminates the possibility of loops occurring

### ELOs
#### Describe Network Address Translation (NAT)
* assigns a public IP address to a computer or group of computers when sending traffic outside the internal network
* When the response comes back, the same device translates the public IP address back to the corresponding private IP address to deliver the message to the internal device
* 3 Primary Types
  * One-to-One: provides direct mapping between internal and external address
  * Dynamic: multiple internal devices to share a smaller number of public IP addresses
  * Port Address Translation (PAT): (aka NAT Overload) maps multiple internal IP addresses to a single public IP address by using different port numbers for each session
 
#### Describe the benefits of different network devices
* Router:
  * manages traffic between networks by transmitting data packets to IP addresses
  * Some routers also act as Wireless Access Points (WAP) that provide Wireless Fidelity (WiFi) but are also capable of wired connections such as ethernet
  * provide network segmentation and filtering capabilities supporting Defense in Depth strategies
* Layer 3 Switch:
  * switch offering routing capabilities, and an easier configuration of subnets because a router is not required between each VLAN
  * add additional network segmentation instead of relying on upstream routers
*

#### Identify common tunneling protocols and Virtual Private Network (VPN) concepts
*  done by establishing a digital connection between the host and VPN provider, thereby creating a 1:1 connection that encrypts the data transmissions, masking IP addresses, and avoiding some website blockers and firewalls (depending on the settings
*   virtual because there are no physical cables in the connection process, private because it is designed for encryption and security, and networked because it links the host computer directly to the VPN server

#### Describe the concept of packet sniffing and Packet Capture (PCAP)
* capture and analyze network traffic
* capture traffic in promiscuous mode, allowing them to intercept and log all traffic on the network segment, not just the traffic addressed to the NIC
* Tools: Wireshark, Tshark, TCPDump, NetworkMiner, Zeek, and Suricata
* uses the most space and scales the worst but provides the most in-depth information due to being a bit-for-bit copy

#### Differentiate Type 5 versus Type 7 password hashing and encryptions

#### Describe the Open Systems Interconnection (OSI) model
* 7 layer model that describes the process of communication between hardware and network devices

#### Differentiate between routable and non-routable spaces as it relates to IP addresses

#### Describe the importance of Request for Comments (RFC)
* standardize the internet technologies seen and interacted with every day. They are formal documents from the Internet Engineering Task Force (IETF) that outline standards and specifications for topics pertaining to networking and the internet
* allow for interoperability between developers
  
#### Explain the information contained within IPv4 and IPv6, Transmission Control Protocol (TCP), User Datagram Protocol (UDP), and Internet Control Message Protocol (ICMP) headers

#### Understand cloud concepts such as Software as a Service (SaaS), Platform as a Service (PaaS), and Infrastructure as a Service (IaaS)
* PaaS:
  * provides a comprehensive platform for developers to build, deploy , and manage applications without managing infrastructure
  * ready-to-use
  * enhances productivity
* SaaS:
  * software applications over the internet on a subscription basis
  * no need for local installation
  * cost effective way to access a range of services
* IaaS:
  * provides virtual machines, storage, and networking over the internet
  * pay as you go
  * reduces operational and maintence burden
 
#### Understand the function of common networking appliances

#### Explain Authentication, Authorization and Accounting (AAA) in Remote Authentication Dial-In User Service (RADIUS), Terminal Access Controller Access-Control System (TACACS+), Kerberos, and New Technology LAN Manager (NTLM)
* RADIUS is a networking protocol that provides centralized Authentication, Authorization, and Accounting (AAA) management.
* TACACS+ is an authentication protocol typically providing centralized validation to access a router or Network Attached Storage (NAS)
  * combines AAA into one protocol
  * Easily integrates with AD resources and Multi-Factor Authentication (MFA) methods
* Windows New Technology LAN Manager (NTLM) is a proprietary suite of security protocols that offer AAA tools
  * Windows AD resource management, it consists of a challenge-response authentication protocol to allow access
  * several known security vulnerabilities that make it less secure than more contemporary protocols such as Kerberos

#### Differentiate between Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS)
* 



## Intro to Opertations

### ELOs

#### CPT Operations


#### Objectives, Effects, and Guidance
* PLANORD
  * outlines the planning and execution of a specific operation or mission
  * datails info such as mission's objectives, concept of operations, intel assesssments, available resources, timelines, and command structure
  * ensures there is a clear coordinated approach
* TASKORD:
  * assign tasks and responsibilities to units and individuals involved in an operation or mission
  * outlines the precise tasks, objectives, timelines, and coordination requirements for each element of the force, ensuring that everyone understands their role and the overall mission's goals

#### Terrain Identification and Prioritization
* during Mission Analysis process, the cpt will condict a technical survey of the supported commander’s network to identify MRT-C
* Key Terrain Cyber (KT-C):
  * any cyberspace terrain that affords any combatant a position of marked advantage when held
  * including security devices that control access, observation points, and MRT-C
* Mission Relevant Terrain (MRT-C):
  *  all devices, internal or external links, Operating Systems (OS), services, applications, ports, protocols, hardware, and software on servers required to enable the function of a critical asset
* terrain identification helps assess threats and relevant information

#### Capability Analysis and Force Allocation
* analysis of operating picture and equipment
* tradecraft needs, limitations, noise level
* refine objectives and desired effects based on plans
* Operational Impact Validation: reherse the mission in a lab with virtually replicated networks and validate capabilities 

#### Orders Production and Dissemination
* operational level orders production team receives the final outputs from Step 3. Outputs are developed into a formal operations order or TASKORD

#### Tactical Planning and Mission Execution
* create a tactical mission plan that:
  * articulates objectives and tasks
  * pairs capabilities to tasks
  * establishes data collection, sensor management plan, mission phases, contracts, and communications plan
  * develop contingencies and tactical assessments
* prior to mission:
  * CONOP briefing to the Supported Commander, Higher HQ Commander, and/or Mission Owner IT/Signal support personnel
  * tabletop exercise with analytic, admin, and logistical support personnel
 * Provide commanders and staff with daily SITREPs to make informed decisions during mission execution
* Workflow:
  * validate operations of equipment
  * hunt for suspicious events and IoC
  * find the scope of the IoC
  * report findings to the ME leador a SOP dictate
* After Action Review (AAR):
  * evaluate and analyze the intended and actual outcomes of an event, project, or operation
  *  identify strengths, weaknesses, decisions to sustain or improve future missions, and areas for improvement, enabling organizations to enhance their performance in future endeavors

#### Briefings
* In-Brief: the mission purpose, CONOP, intel, and expected actions
* Out-Brief: reiterates the mission purpose and details any deviations from what was expected

#### Mission Resources and Platforms



## Intro to Tooling

### ELOs

#### Cisco Internetworking Operating System (IOS)


#### Suricata


#### Scanning


#### Security Information and Event Management (SIEM) technologies


#### Packet Capture (PCAP) and analysis tools


#### Remote administration


## Threat Hunting I

* a large amount of get request in the beginning of traffic could be indicitive of brute force occuring
* http user agent of HYDRA could be an indicator of password spraying
* Password Spray Attack:
  * cyber attack in which an attacker attempts a few commonly used passwords or a list of commonly used passwords against a large number of usernames or accounts. This attack is designed to evade account lockout mechanisms, as the attacker tries only a limited number of passwords per account, reducing the risk of being detected






