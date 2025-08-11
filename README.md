# awesome-threat-hunting

## File Analysis

- **Online - File Analysis**
  - [VirusTotal](https://virustotal.com/)
  - [Hybrid Analysis - Falcon Sandbox](https://hybrid-analysis.com/) - Uses detections from CrowdStrike Falcon Sandbox
  - [Recorded Future Triage](https://tria.ge/) - Focused around threat hunters & DFIR analysts. Offers a hosted interactive sandbox for opening files and URLs.
  - [InQuest Labs - Deep File Inspection](https://labs.inquest.net/dfi) 
  - [Cuckoo 3 - cert.ee](https://cuckoo-hatch.cert.ee/) - Cuckoo 3 - Maintained by CERT Estonia 
  - [Cuckoo 2 - cert.ee](https://cuckoo.cert.ee/) - Cuckoo 2.0.7 - Maintained by CERT Estonia
  - [Threat.Zone](https://app.threat.zone/)
  - [Nucleon Malprob](https://malprob.io/)
  - [Filescan.io](https://www.filescan.io/scan) 
  - [UnpacMe](https://www.unpac.me/)
    
- **Online - File Analysis - Extensions**
  - [VSCan](https://vscan.dev/) - VSCode Extensions 
  - [CRXcavator](https://crxcavator.io/) - Browser Extensions (Edge, Firefox, Chrome)

- **Offline/Self-Hosted - File Analysis**
  - [Capa](https://github.com/mandiant/capa)
  - [Strelka](https://github.com/target/strelka) - Used in [Security Onion 2.4](https://docs.securityonion.net/en/2.4/strelka.html)
  - [Cuckoo 3](https://github.com/cert-ee/cuckoo3)
  - [Yara CLI](https://yara.readthedocs.io/en/v3.4.0/commandline.html) - Yara CLI can be used with rulesets to scan files at rest. 

## Threat Intelligence

Be careful when downloading live malware samples. 
Detection rules may be picked up by AV as malicious.

  - **Threat Intelligence Portals**
    - [LevelBlue OTX](https://otx.alienvault.com/)
    - [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
    - [PulseDive](https://pulsedive.com/)

- **Search Engines - Indicators of Compromise (IoC)**
    - [Talos Intelligence Search](https://talosintelligence.com/reputation_center)
    - [hunting.abuse.ch](https://hunting.abuse.ch/) -  Hunt across all abuse.ch platforms with one simple query. (IP, Domain, Hashes)
    - [InQuest Labs - IoC DB](https://labs.inquest.net/iocdb)
    

- **Search Engines - Malware**
  - [MalwareBazaar](https://bazaar.abuse.ch/)
  - [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
  - [Windows Defender Security Intelligence - Threat Intel Search](https://www.microsoft.com/en-us/wdsi/threats/threat-search)
  - [FortiGuard Labs - Threat Intel Search](https://www.fortiguard.com/threatintel-search)
  - [Trend Micro - Threat Encyclopedia](https://www.trendmicro.com/vinfo/us/threat-encyclopedia)
  - [SonicWall Capture Labs - Threat Catalog, Anti-Virus & Anti-Spyware](https://capturelabs.sonicwall.com/m/feature/catalog/anti-virus)

- **Detection Engineering**
    - [Elastic Detection Rules](https://elastic.github.io/detection-rules-explorer/)
    - [Florian Roth's IoC Signature Base](https://github.com/Neo23x0/signature-base)
    - [Elastic Security Yara Rules](https://github.com/elastic/protections-artifacts/tree/main/yara)
    - [InQuest Labs - Yara Rules](https://github.com/InQuest/yara-rules)
    - [Filescan.io - Yara Rules](https://github.com/filescanio/fsYara)
    - [Yara Forensic Rules](https://github.com/Xumeiquer/yara-forensics)

## Endpoint Security

- **Incident Response Tools - Endpoint**
  - [Chainsaw](https://github.com/WithSecureLabs/chainsaw) - Windows
  - [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - Windows
  - [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) - Windows

- **Endpoint Investigation Tools**
  
  - [osquery](https://github.com/osquery/osquery/releases) - Windows/Linux
  - [Rapid7 Velociraptor](https://docs.velociraptor.app/) - Windows/Linux
  - [Microsoft Attack Surface Analyzer](https://microsoft.github.io/AttackSurfaceAnalyzer/index.html) - Windows
  - [ESET SysInspector](https://www.eset.com/int/support/sysinspector/) - Windows
  - [Lynis](https://cisofy.com/lynis/#introduction) - Linux/macOS

These are more focused around event logs and system configuration auditing, rather than network traffic inspection. Some of the above tools do have added functionality for packet capture, but they are not dedicated network analysis tools.

- **Investigation References - Windows**

  - [MyEventID - Windows Event ID Lookup](https://www.myeventlog.com/)
  - [EventSentry - Windows Sysmon Event Reference](https://system32.eventsentry.com/sysmon/events)
  - [EventSentry - Windows Applocker Event Reference](https://system32.eventsentry.com/applocker/events)

- **Endpoint Compliance Validation - Microsoft Windows**
  - [Key Security Events for PCI-DSS Compliance](https://system32.eventsentry.com/compliance/PCI-DSS)
  - [Key Security Events for NIST 800-171 Compliance](https://system32.eventsentry.com/compliance/NIST%20800-171)
  - [Key Security Events for CJIS Compliance](https://system32.eventsentry.com/compliance/CJIS)
  - [Key Security Events for CMMC Compliance](https://system32.eventsentry.com/compliance/CMMC)
  - [Key Security Events for ISO 27001:2013 Compliance](https://system32.eventsentry.com/compliance/ISO%2027001:2013)
  - [Key Security Events for HIPAA Compliance](https://system32.eventsentry.com/compliance/HIPAA)
  - [Key Security Events for NIST SP 800-53 Compliance](https://system32.eventsentry.com/compliance/NIST%20SP%20800-53)

## Network Security

- **Network Investigation Tools**
  - [pktmon](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon) - Windows - Packet Monitor (Pktmon) is an in-box, cross-component network diagnostics tool for Windows. It can be used for advanced packet capture and event collection, drop detection, filtering, and counting.
  - [Suricata](https://suricata.io/) - Windows/Linux
  - [NetworkMiner](https://www.netresec.com/?page=networkminer) - Windows/Linux - NetworkMiner is an open source network forensics tool that extracts artifacts, such as files, images, emails and passwords, from captured network traffic in PCAP files. NetworkMiner can also be used to capture live network traffic by sniffing a network interface.
  
- **Investigation References**
  - [Nmap2CSV](https://github.com/ndr-repo/Nmap2CSV) - Create a local reference file of ports & protocols according to latest Nmap detection intel
  - [IANA - Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
    
- **Enterprise WAF References - L7 Application Detections**
  - [Cisco - Secure Firewall Application Detectors (App-ID)](https://appid.cisco.com)
  - [Palo Alto Networks - Application Research Center](https://applipedia.paloaltonetworks.com/)
  - [FortiGuard Labs - Application Control](https://www.fortiguard.com/appcontrol)
    
