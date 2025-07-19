# awesome-threat-hunting
A public repository to share resources for cyber threat hunters.

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
  - [Mandiant/Google - Capa](https://github.com/mandiant/capa)
  - [Target - Strelka](https://github.com/target/strelka) - Used in [Security Onion 2.4](https://docs.securityonion.net/en/2.4/strelka.html)
  - [CERT Estonia - Cuckoo 3](https://github.com/cert-ee/cuckoo3)
   

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
    - [FortiGuard Labs - Threat Intel Search](https://www.fortiguard.com/threatintel-search)

- **Search Engines - Malware**
  - [MalwareBazaar](https://bazaar.abuse.ch/)
  - [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)

- **Detection Engineering**
    - [Elastic Detection Rules](https://elastic.github.io/detection-rules-explorer/)
    - [InQuest Labs - Yara Rules](https://github.com/InQuest/yara-rules)
    - [Filescan.io - Yara Rules](https://github.com/filescanio/fsYara)
    - [Yara Forensic Rules](https://github.com/Xumeiquer/yara-forensics)

## Endpoint Security

- **Endpoint Investigation Tools**
  
  - [osquery](https://github.com/osquery/osquery/releases) - Windows/Linux
  - [Rapid7 Velociraptor](https://docs.velociraptor.app/) - Windows/Linux
  - [Microsoft Attack Surface Analyzer](https://microsoft.github.io/AttackSurfaceAnalyzer/index.html) - Windows
  - [ESET SysInspector](https://www.eset.com/int/support/sysinspector/) - Windows
  - [Lynis](https://cisofy.com/lynis/#introduction) - Linux/macOS
      
## Network Security

- Enterprise WAF References - L7 Application Detections
  - [Cisco - Secure Firewall Application Detectors (App-ID)](https://appid.cisco.com)
  - [Palo Alto Networks - Applipedia](https://applipedia.paloaltonetworks.com/)
  - [FortiGuard Labs - Application Control](https://www.fortiguard.com/appcontrol)
    
- Detection Search - Antivirus & Threat Protection Vendors
  - [FortiGuard Labs - WebFilter](https://www.fortiguard.com/webfilter) 
  - [Zscaler - Zulu URL Risk Analyzer](https://threatlabz.zscaler.com/tool/url-analysis)
  - [Norton SafeWeb - URL Lookup](https://safeweb.norton.com/)
  - [ProofPoint Dynamic Reputation - IP Lookup](https://ipcheck.proofpoint.com/)
  - [WebRoot BrightCloud - URL/IP Lookup](https://www.brightcloud.com/tools/url-ip-lookup.php)
