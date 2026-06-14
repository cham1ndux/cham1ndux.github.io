---
title: Uncovering an APT28-Inspired Attack on Global Freight UA - XINTRA
date: 2026-06-14 00:00:00
categories: [DFIR]
tags: [dfir]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/gfu.png
  lqip:
  alt: Global Freight - APT28 
---

## THREAT ACTOR

This lab is modeled on tradecraft associated with APT28, the Russian GRU-linked espionage group commonly tracked as Fancy Bear / Unit 26165. The closest public analog is CISA’s May 21, 2025 advisory on Russian GRU targeting of Western logistics entities and technology companies supporting Ukraine.

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141a

## CONTRIBUTORS:
- Adversarial Emulator Team: [@ZephrFish](https://www.linkedin.com/in/norecruiters/)
- Incident Responder: [@r3nzsec](https://www.linkedin.com/in/renzoncruz/)

## SCOPING NOTE

Global Freight UA is a high-value espionage target because it coordinates Ukraine-bound freight, stores partner and contract information, maintains logistics records in SQL, and uses camera infrastructure to monitor physical movement and border-related activity. In this lab, defenders are responding to suspicious activity observed between January 21, 2026 and January 25, 2026 across `GFUA-WKS01`, `GFUA-WKS02`, `GFUA-FS01`, `GFUA-MSSQL`, `GFUA-DC01`, `GFUA-cctv`, `GFUA-cam01`, and supporting proxy telemetry from `GFUA-PRX01`.

Velociraptor triage collections, ELK, mailbox artifacts, browser artifacts, proxy telemetry, and selected AD CS artifacts are available for analysis. Systems `GFUA-elk` and `GFUA-jump` are out of scope.

Note: Any activity associated with the LabAdmin setup account should be treated as lab setup rather than threat activity.

## NETWORK DIAGRAM

Below is an image of the infected part of the network that the client is concerned with.

![](https://storagepublic.xintra.org/public/i/20260610-035231/FREIGHT.jpg)


## Initial Access

Our investigation began with an analysis of Windows Event Logs to identify abnormal authentication activity within the environment. 

During the review of authentication logs, we observed multiple successful NTLM network logons associated with the accounts `ichernysh`, `dkovalenko`, and `kpavlenko`. These logons originated from `10.53.67.11` and targeted several systems, including `GFUA-DC01`, `GFUA-WKS01`, `GFUA-WKS02`, and `GFUA-MSSQL`. 

<img src="/assets/img/gf01.png" alt="" />

Notably, the source hostname recorded in the events was `CHAOS-CRACK`, which differs from the expected hostname shown in the network inventory. This discrepancy suggests that the system at `10.53.67.11` may have been compromised and was being used by the attacker to perform authentication activity throughout the environment. As a result, the investigation focused on this host as the likely source of lateral movement.

To further investigate the source of the suspicious authentication activity, we examined the Windows Event Logs on the workstation `10.53.67.11 (GFUA-WKS01)`  during the same timeframe. This review revealed the execution of several suspicious processes that were inconsistent with normal user activity.

<img src="/assets/img/gf02.png" alt="" />

The presence of these processes shortly before and during the observed authentication events suggests that the workstation may have been compromised and was being actively used by the attacker. Given that multiple NTLM logons originated from this host, the suspicious process activity provides additional evidence that `10.53.67.11` was being leveraged as a staging point for further actions within the environment.

As a result, our investigation shifted to analyzing the process execution chain on the host to determine the initial access vector, identify any malicious tools deployed by the attacker, and understand how the compromise progressed throughout the network.

### Identification of the Initial Compromised Host
 
During the review of suspicious process activity on `GFUA-WKS01`, we identified a suspicious executable created under the user's local Office directory: `C:\Users\ichernysh\AppData\Local\Microsoft\Office\svc.exe`. Based on the Sysmon file creation event, this file was created on `2026-01-21` by PowerShell running under the user context `GFUA\ichernysh`.

<img src="/assets/img/gf03.png" alt="" />

To understand how this PowerShell activity was triggered, we investigated the associated process ID `11628` and reviewed the process creation chain. The logs showed that PowerShell was launched by `WINWORD.EXE`, indicating that Microsoft Word was the parent process. The parent command line referenced a macro-enabled document located at `C:\Users\ichernysh\Documents\CargoPortalReview\огляд вантажу, деталі вантажу.docm`.

<img src="/assets/img/gf04.png" alt="" />

This behavior strongly suggests that the user opened a malicious Office document, which executed embedded macro code. The macro then launched PowerShell to extract or deploy `svc.exe` into the Office directory. Since Office documents do not normally create executable files through PowerShell, this activity was treated as the likely initial execution stage of the compromise.

To trace the origin of the malicious document, we continued analyzing the file creation events associated with the macro execution chain. The investigation revealed that the macro-enabled document `огляд вантажу, деталі вантажу.docm` was extracted from a ZIP archive named `CargoPortalReview.zip`.

Sysmon file creation logs showed that the document was written to the user's temporary extraction directory shortly after the ZIP archive was accessed. This indicates that the archive was opened and its contents were extracted before the malicious document was executed.

<img src="/assets/img/gf05.png" alt="" />

Further analysis of the ZIP archive's origin revealed that `CargoPortalReview.zip` had been created by `OUTLOOK.EXE` within the user's Outlook cache directory. 

<img src="/assets/img/gf06.png" alt="" />

This behavior confirms that the archive was delivered through Microsoft Outlook, most likely as an email attachment.

To identify the initial delivery mechanism, we examined the Outlook PST file belonging to `GFUA\ichernysh`. This analysis led to the discovery of a phishing email containing the malicious attachment `CargoPortalReview.zip`, which had previously been linked to the execution of the macro-enabled document.

<img src="/assets/img/gf07.png" alt="" />

The email was sent from `cargoreview@gmail.com` and was crafted to appear as a legitimate logistics-related communication. The message referenced updated cargo inspection and transit coordination procedures and encouraged the recipient to review the attached archive. To increase its credibility, the email included logistics-specific terminology and provided a password for opening the protected archive.

This finding confirms that the compromise originated from a phishing email. After receiving the message, the user opened the attached ZIP archive, extracted the embedded macro-enabled document, and executed it. The document subsequently launched PowerShell, resulting in the creation of the malicious payload svc.exe and the successful compromise of the workstation.

After confirming that the phishing email delivered the archive `CargoPortalReview.zip`, we proceeded to analyze the contents of the extracted ZIP file. The archive contained two macro-enabled Microsoft Word documents:

<img src="/assets/img/gf08.png" alt="" />

As the first step, we focused on analyzing ог`ляд вантажу, деталі вантажу.docm`, since this document was directly observed in the parent process chain that launched PowerShell. This made it the primary suspect for the initial macro execution and payload deployment activity observed on `GFUA-WKS01`.

### Analysis of ляд вантажу, деталі вантажу.docm

We analyzed the macro-enabled document `огляд вантажу, деталі вантажу.docm` using `olevba` to understand its embedded VBA behavior. The analysis revealed that the document contained an obfuscated VBA macro designed to execute automatically when the document was opened. This was achieved through the use of `AutoOpen` and `Document_Open` functions, both of which called the main macro routine.

The macro first performed several environment checks before executing its payload. These checks included verifying the operating system, checking the number of running processes, inspecting the username and computer name, and searching for common analysis tools such as `Wireshark`, `Procmon`, `x64dbg`, `OllyDbg`, `IDA`, and `Fiddler`. These checks indicate that the macro attempted to detect sandbox or analysis environments before continuing execution.

<img src="/assets/img/gf09.png" alt="" />

After passing these checks, the macro created a working directory under `%LOCALAPPDATA%\Microsoft\Office`. It then wrote and extracted an embedded ZIP archive named `Zeyilname.zip` into this directory. The extracted content included files such as `svc.exe`, `zqtxmo.bat`, and `WindowsCodecs.dll`.

<img src="/assets/img/gf10.png" alt="" />

The macro used PowerShell with the `Expand-Archive` command to extract the ZIP file. This aligns with the earlier Sysmon evidence showing PowerShell execution from Microsoft Word and the creation of `svc.exe` inside the user's local Office directory.

The macro then attempted to execute a file named `IMG-387470302099.jpg.exe`. Although the filename appears to reference a JPG image, the double extension indicates that it is actually an executable. This is a common deception technique used to make malicious files appear less suspicious to users or analysts.

The code comments and behavior suggest a staged payload execution flow. The macro extracted the payload files, executed the sideloading host, and then attempted to clean up evidence by deleting temporary files, clearing Office recent file entries, removing Word MRU registry entries, and deleting selected artifacts from the extraction directory.

<img src="/assets/img/gf11.png" alt="" />

Overall, the macro analysis confirmed that `огляд вантажу, деталі вантажу.docm` was malicious. It was designed to evade analysis, extract additional payloads, execute them using PowerShell and Windows scripting, and remove traces of execution. This finding supports the earlier timeline showing that the phishing email attachment was the initial access vector used to compromise `GFUA-WKS01`.

### Analysis of Оновлення Порталу Логістики – Міністерство Інфраструктури України.docm Analysis

We then analyzed the second macro-enabled document, `Оновлення Порталу Логістики – Міністерство Інфраструктури України.docm`, to determine whether it contained additional malicious functionality.

The VBA code showed that the macro was configured to execute automatically through the AutoOpen function when the document was opened. Unlike the first document, this macro did not directly extract or execute a payload. Instead, it created a new Outlook calendar appointment using the local Microsoft Outlook application.

<img src="/assets/img/gf12.png" alt="" />

The calendar invite was titled `Q1 Logistics Sync - Updated Invite` and was configured as a Microsoft Teams meeting reminder. However, the suspicious part was the reminder sound configuration. The macro set the reminder sound file to a remote UNC path: `\18.204.55.15\share\logistics.wav`.

This behavior is significant because when Outlook attempts to access a remote UNC path, Windows may automatically attempt NTLM authentication to that external server. As a result, the attacker could potentially capture the user's NTLM authentication material without requiring the user to manually enter credentials.

This technique is consistent with Outlook-based forced authentication behavior, similar to the abuse pattern associated with [CVE-2023-23397](https://unit42.paloaltonetworks.com/threat-brief-cve-2023-23397/). In this case, the macro abused Outlook calendar reminder functionality to force the victim machine to connect to an attacker-controlled SMB share.

Based on this analysis, the second document was also confirmed to be malicious. While the first document focused on payload execution, this document was designed to trigger outbound authentication to `18.204.55.15`, likely for credential harvesting or NTLM relay preparation.

## Defense Evasion & Anti-Forensics

Further evidence of anti-forensic activity was identified during both the VBA macro analysis and the review of Sysmon logs in Elastic. The malicious macro contained functionality specifically designed to remove artifacts that could reveal the user's interaction with the malicious document.

<img src="/assets/img/gf13.png" alt="" />

As part of its cleanup routine, the macro executed several commands to delete traces of document execution. Process creation logs showed `cmd.exe` being launched to remove entries from the Microsoft Word File MRU (Most Recently Used) registry key:

`HKCU\Software\Microsoft\Office\16.0\Word\File MRU`

By deleting these registry entries, the attacker attempted to remove references to recently opened Word documents, making it more difficult for investigators to determine which document initiated the compromise.

<img src="/assets/img/gf14.png" alt="" />

In addition, the logs showed another cmd.exe process executing commands to delete temporary files from the user's `%TEMP%` directory. This activity aligns with the cleanup functions observed in the VBA code and demonstrates an attempt to eliminate artifacts generated during payload extraction and execution.

## Persistence

Following the successful execution of the payload, the attacker established persistence to ensure continued access to the compromised system. Analysis of process creation logs revealed that `svc.exe`, located in `C:\Users\ichernysh\AppData\Local\Microsoft\Office`, was configured to execute automatically through multiple persistence mechanisms.

The first persistence method involved the creation of a Run registry key under the current user's profile:

<img src="/assets/img/gf15.png" alt="" />

A registry value named `ServiceSync` was added, pointing to `svc.exe`. This ensures that the malware is automatically launched each time the user logs into Windows.

Further investigation identified a second persistence mechanism using Windows Scheduled Tasks. The attacker created a scheduled task named `BackupSync`, configured to execute `svc.exe` on a daily schedule.

<img src="/assets/img/gf16.png" alt="" />

 By leveraging both a startup registry key and a scheduled task, the attacker increased the likelihood that the malware would remain active even if one persistence mechanism was discovered and removed.

## Command and Control

 To better understand the capabilities of the deployed payload, we performed additional analysis on `svc.exe`. Initial indicators suggested that the executable was not a simple standalone malware sample but rather a command-and-control (C2) agent designed to provide remote access to the attacker.

 Using the [Havoc Extractor tool](https://github.com/r3nzsec/havoc-extractor), we extracted and analyzed the embedded configuration from `svc.exe`. The analysis confirmed that the malware was a Havoc Demon agent, an open-source post-exploitation framework commonly used by red teams and threat actors for command-and-control operations.

 <img src="/assets/img/gf17.png" alt="" />

 The extracted configuration revealed that the agent was configured to communicate with the domain `login.cargo-review.com`, which resolved to the IP address `34.205.15.136`. Communication with the C2 server was performed over HTTP using POST requests, allowing the compromised host to receive commands and return execution results to the attacker.

 Further analysis showed that the payload was configured to inject into `RuntimeBroker.exe`, a legitimate Windows process. This technique enables the malware to blend in with normal system activity and makes detection more difficult by executing malicious code within a trusted process.

 The extracted configuration also referenced `AES-128-CBC (HEADLACE)` encryption, indicating that communications between the infected host and the command-and-control server were encrypted. This aligns with the lab scenario's use of `HEADLACE-style` payload staging, where encrypted communications are used to conceal attacker activity and hinder network-based detection.

 Based on these findings, we concluded that svc.exe served as the primary command-and-control beacon deployed on `GFUA-WKS01`. Once executed and persisted on the system, the malware enabled the attacker to maintain remote access, issue commands, deploy additional tooling, and continue post-exploitation activities within the compromised environment.

## Discovery & Reconnaissance

 Following the establishment of command-and-control access, the attacker began performing reconnaissance activities on the compromised host. Analysis of Windows event logs revealed the execution of several built-in Windows commands, including:

 ```bash
> arp -a
> nslookup
> net view
> ipconfig /all
> hostname
> whoami /all
```
These commands were used to gather information about the local system, network configuration, domain environment, and available hosts. The activity indicates that the attacker was enumerating the environment to identify potential targets and plan subsequent lateral movement within the network.

## Lateral Movement

Following the initial compromise and reconnaissance activities, the attacker began expanding their presence within the environment. Analysis of SMB-related events revealed that the compromised workstation `10.53.67.11 (GFUA-WKS01)` accessed the file server `GFUA-FS01` through a network share.

 <img src="/assets/img/gf18.png" alt="" />

The logs show that a suspicious executable, `svc.exe`, was written to the shared directory `\*\SharedDocs\Service_Updates\` on `GFUA-FS01`. This activity indicates that the attacker used SMB file-sharing functionality to transfer their command-and-control payload from the compromised workstation to the file server.

The placement of the payload on a shared network location suggests an attempt to stage malware for execution on additional systems or to facilitate further lateral movement within the environment.

Following the deployment of `svc.exe` to `GFUA-FS01`, the attacker modified their tooling to improve stealth and persistence. Analysis of file access and process execution logs revealed that the original `svc.exe` payload was removed and replaced with a renamed copy, `ShipmentService.exe`, within the shared directory `G:\Service_Updates\` on the file server.

 <img src="/assets/img/gf19.png" alt="" />

Shortly after staging the renamed payload, the attacker established persistence on `GFUA-FS01` by creating a scheduled task named `ShipmentScheduleSync`. The task was configured to execute `G:\Service_Updates\ShipmentService.exe` on a recurring daily schedule.

 <img src="/assets/img/gf20.png" alt="" />

 The renaming of the payload to `ShipmentService.exe` allowed it to blend in with the logistics-themed environment and appear as a legitimate business-related service.

 The attacker's activity was not limited to `GFUA-FS01`. Further investigation revealed evidence of lateral movement to `GFUA-WKS02`, where additional persistence mechanisms were established.

Process creation logs showed the execution of a registry modification command that added a new value under the Windows Run registry key:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

 <img src="/assets/img/gf21.png" alt="" />

The registry value, named `ShipmentSchedule`, was configured to launch `G:\Service_Updates\ShipmentService.exe` automatically whenever the user logged into the system.

To determine the extent of the compromise, we searched the event logs for the MD5 hash associated with the malicious payload. This allowed us to identify all systems where the same malware sample had been executed or observed.

 <img src="/assets/img/gf22.png" alt="" />

The results revealed that the payload was present on five systems within the environment: 

- GFUA-WKS01
- GFUA-WKS02
- GFUA-DC01
- GFUA-FS01
- GFUA-MSSQL

This confirms that the attacker had successfully moved laterally beyond the initially compromised workstation and established a presence across multiple critical assets.

Notably, the affected systems included the Domain Controller, File Server, and SQL Server, indicating that the attacker had expanded their access into the core infrastructure of the environment.

 <img src="/assets/img/gf23.png" alt="" />

To further validate the spread of the malware, we reviewed the process names associated with the identified MD5 hash across the affected systems. Although the payload maintained the same MD5 hash, it was observed operating under multiple filenames, including `svc.exe`, `ShipmentService.exe`, and `Viewer.exe`.

During the investigation of `GFUA-WKS01`, PowerShell Script Block logs (Event ID 4104) revealed the execution of a network reconnaissance script under the account `obondarenko`. Analysis of the script showed that it was designed to perform web service enumeration by scanning common web application ports, including `80`, `443`, `8080`, `9090`, and `9001`.

 <img src="/assets/img/gf24.png" alt="" />

The script issued HTTP/HTTPS requests to identify active web services and collect server response information. This activity indicates that the attacker was conducting internal reconnaissance to discover accessible web-based systems and identify potential targets for further exploitation within the environment.

Further analysis of process creation logs on `GFUA-WKS01` revealed that the attacker executed a PowerShell command to query the `SecurityCenter2` WMI namespace and enumerate installed antivirus products on the system.

 <img src="/assets/img/gf25.png" alt="" />

The command utilized `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct`, a common reconnaissance technique used to identify endpoint security solutions and defensive controls present on a host. By gathering this information, the attacker could assess the security posture of the system and adapt their tools or techniques to avoid detection.

##  Privilege Escalation

Another notable finding on `GFUA-WKS01` was the execution of the malicious payload `svc.exe` with elevated privileges. Process creation logs showed that `svc.exe` was launched from `C:\Users\ichernysh\AppData\Local\Microsoft\Office\` and executed with a High Integrity Level, indicating that the process was running with elevated permissions.

 <img src="/assets/img/gf26.png" alt="" />

The process was spawned by `explorer.exe` under the context of `GFUA\ichernysh`, suggesting that the payload was executed interactively after the user logged on. Running with elevated privileges would have provided the malware with broader access to system resources, allowing it to perform privileged operations, establish persistence, and interact with other systems more effectively.

### Active Directory Certificate Services (AD CS) Abuse

As the investigation progressed to `GFUA-DC01`, we identified evidence suggesting that the attacker abused Active Directory Certificate Services (AD CS) to escalate privileges and establish a more persistent form of access within the domain.

 <img src="/assets/img/gf27.png" alt="" />

Analysis of the certificate authority database located in `C:\Windows\System32\CertLog` revealed certificate enrollment activity occurring during the timeframe of the incident. By reviewing the CA log records, we identified a certificate request submitted by the user `GFUA\ichernysh` on `January 22, 2026, at 10:09 PM`.

 <img src="/assets/img/gf28.png" alt="" />

Further examination showed that the certificate was issued using the `RemoteAccessUsers` certificate template. This finding is significant because the template was configured in a manner that allowed it to be abused for certificate-based authentication. By successfully enrolling a certificate through this template, the attacker could obtain a valid authentication certificate tied to the compromised account.

To determine whether the `RemoteAccessUsers` certificate template could have been abused for privilege escalation, we reviewed its configuration in detail. The template settings revealed several characteristics commonly associated with vulnerable AD CS templates.

 <img src="/assets/img/gf29.png" alt="" />

Most notably, the template had the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled. This setting allows the certificate requester to supply the subject information during enrollment rather than having it automatically populated from Active Directory. In a misconfigured environment, this can allow an attacker to request a certificate on behalf of another user.

The template was also configured for Client Authentication, meaning that any issued certificate could potentially be used for domain authentication through `PKINIT` or certificate-based logon mechanisms.

Additionally, the template permissions showed that enrollment rights were granted to broad groups, including `Domain Users`. This allowed standard domain accounts, such as the compromised `ichernysh` account, to request certificates using the template without requiring elevated privileges.

Further evidence of certificate template abuse was identified within the `attrib` records of the Certificate Authority database. These records store the attributes submitted by the certificate requester during the enrollment process.

Analysis of the request attributes showed that the certificate was issued using the `RemoteAccessUsers` template. More importantly, the requester supplied a custom Subject Alternative Name (SAN) value of `upn=dkovalenko@gfua.local`.

  <img src="/assets/img/gf30.png" alt="" />

This finding is significant because the certificate request was submitted using the compromised `ichernysh` account, yet the SAN field was populated with the UPN of a different user, `dkovalenko`. The ability to specify an arbitrary SAN is a direct result of the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` setting identified in the template configuration.

By requesting a certificate containing `dkovalenko`'s UPN, the attacker could obtain a valid authentication certificate that would be treated as belonging to `dkovalenko` during certificate-based authentication. This effectively allowed the attacker to impersonate another domain user without knowing that user's password.

## Credential Access

During the investigation of `GFUA-DC01`, multiple PowerShell transcript files were recovered from the system. Analysis of these transcripts revealed that the attacker executed `ntdsutil.exe` using the Install From Media (IFM) functionality to create a copy of the Active Directory database.

Specifically, the attacker executed the following command:

```bash
ntdsutil.exe "activate instance ntds" ifm "create full C:\temp\[a-z]{3}" quit quit
```
<img src="/assets/img/gf31.png" alt="" />

The create full option generates a complete offline copy of the Active Directory database, including `ntds.dit`, which contains domain account information and password hashes. This technique is commonly used by attackers to obtain credential material from a Domain Controller without directly interacting with the live database.

<img src="/assets/img/gf32.png" alt="" />

Further analysis identified an Active Directory directory containing `ntds.dit` and `ntds.jfm` files within the attacker's staging location. The staging directory followed a three-character naming convention, which aligns with the naming pattern observed in the `gfc` directory found under `C:\SharedDocs\Service_Updates\` on `GFUA-FS01`.

This correlation suggests that the attacker copied the Active Directory database from `GFUA-DC01`, staged it locally using IFM, and subsequently transferred the data to infrastructure under their control for collection and potential exfiltration.

## Surveillance System Access

As part of the investigation into the attacker's post-compromise activity, we reviewed the browser history artifacts recovered from `GFUA-WKS02`. This analysis revealed multiple visits to the organization's internal surveillance platform hosted on `http://10.53.66.23:9001`, including the `/login`, `/media`, `/dashboard`, and `/settings` pages.

<img src="/assets/img/gf33.png" alt="" />

The page titles associated with these visits identified the application as Kerberos Agent, an internal video surveillance platform deployed on `GFUA-CCTV (10.53.66.23)`. The presence of multiple visits to different application pages indicates that the attacker successfully accessed and interacted with the surveillance system rather than merely browsing to the login page.

<img src="/assets/img/gf34.png" alt="" />

To determine which account was used to access the platform, we examined browser-stored login artifacts. Analysis of the Login Data database, specifically the stats table, revealed an entry associated with `http://10.53.66.23:9001`. The stored username value was identified as `root`, confirming that the attacker accessed the CCTV platform using the `root` account.

These findings demonstrate that the attacker expanded their access beyond traditional IT systems and gained visibility into the organization's surveillance infrastructure, potentially allowing them to monitor operational activity and gather additional intelligence from the compromised environment.

## Exfiltration

During the investigation of `GFUA-FS01`, we identified a suspicious PowerShell script named `ManifestSync.ps1`. Although the script appeared to be written as a backup service, its behavior showed clear signs of data staging and exfiltration.

<img src="/assets/img/gf35.png" alt="" />

The script was configured to collect files from the file server share `\GFUA-FS01\SharedDocs\Shipment_Schedules\` and stage them locally under `C:\Temp\ShipGFC`. It also referenced CCTV footage from `C:\backup\CCTV\border_crossing`, indicating that the attacker intended to collect both shipment-related documents and surveillance data.

After collection, the script compressed the gathered files into ZIP archives and uploaded them to the external server `http://login.cargo-review.com:9090/upload` using HTTP POST requests. Following successful upload, the script attempted to delete the local archive files, reducing the forensic evidence left on the system.

Although the script was disguised as a legitimate backup process, its staging paths, external upload destination, and cleanup behavior confirm that it was used as an exfiltration mechanism. This activity shows that the attacker moved from persistence and lateral movement into data collection and exfiltration from critical business and surveillance systems.

Further analysis of the PowerShell Script Block (Event ID 4104) logs revealed evidence that the attacker modified the exfiltration script during the intrusion. An earlier version of the script contained a placeholder CCTV source path defined as `C:\backup\CCTV\videos`.

<img src="/assets/img/gf36.png" alt="" />

This path differs from the CCTV collection directory identified in the final version of the script, where the source was updated to the actual surveillance storage location. The change indicates that the attacker was actively developing and refining the script after gaining access to the environment.

After identifying `svc.exe` as the attacker's primary implant on `GFUA-WKS01`, we sought to determine the volume of network traffic generated by the malware during the intrusion. To accomplish this, we examined the System Resource Usage Monitor (SRUM) database, which records historical network usage for applications running on a Windows system.

<img src="/assets/img/gf37.png" alt="" />

The SRUM artifacts were recovered from `C:\Windows\System32\sru\` on `GFUA-WKS01` and parsed to extract network usage records. We then filtered the Network Usage dataset using the Exe Info column to isolate entries associated with `svc.exe`.

<img src="/assets/img/gf38.png" alt="" />

This filtering revealed multiple network usage records tied to `C:\Users\ichernysh\AppData\Local\Microsoft\Office\svc.exe`, spanning several hours after the malware established persistence. The records showed a consistent pattern of outbound network activity, indicating regular communication between the implant and attacker-controlled infrastructure.

Using PowerShell, we filtered the SRUM network usage records for the intrusion timeframe on `2026-01-21` and calculated the total outbound traffic generated by `svc.exe`.

The result showed that `svc.exe` sent a total of` 369,624,295 bytes`, which is approximately `352.50 MB` or `0.34 GB`. This confirms that the malware generated a significant amount of outbound data transfer during the compromise.

<img src="/assets/img/gf39.png" alt="" />

This activity is consistent with command-and-control communication and potential data exfiltration performed by the attacker after persistence was established on `GFUA-WKS01`.

## MITRE ATT&CK Mapping

The observed activity demonstrates strong similarities to publicly reported APT28 tradecraft, particularly techniques described in recent advisories involving credential access, AD CS abuse, lateral movement, persistence, surveillance access, and data exfiltration.

### Mapping the Attack to APT28 Tradecraft

| Attack Stage         | Observed Activity                          | MITRE ATT&CK         | APT28 Alignment                                 |
| -------------------- | ------------------------------------------ | -------------------- | ----------------------------------------------- |
| Initial Access       | Phishing email with CargoPortalReview.zip  | T1566.001            | APT28 frequently uses spearphishing attachments |
| User Execution       | User opened DOCM and enabled macros        | T1204.002            | Common APT28 delivery method                    |
| PowerShell Execution | WINWORD.exe -> powershell.exe               | T1059.001            | Frequently observed in APT28 malware delivery   |
| Defense Evasion      | Sandbox checks, AV enumeration             | T1497, T1518.001     | Similar to HEADLACE and other GRU tooling       |
| Payload Deployment   | svc.exe (Havoc Demon) dropped              | T1105                | Secondary payload staging                       |
| Persistence          | Run Key + Scheduled Tasks                  | T1547.001, T1053.005 | Common persistence mechanisms                   |
| Discovery            | whoami, ipconfig, arp, nslookup, net view  | T1082, T1016, T1049  | Internal reconnaissance                         |
| Credential Access    | CVE-2023-23397 style forced authentication | T1557 / T1187        | Strongly associated with APT28                  |
| AD CS Abuse          | RemoteAccessUsers certificate template     | T1649                | Certificate-based privilege escalation          |
| Lateral Movement     | SMB transfer to FS01                       | T1021.002            | Common internal movement technique              |
| Credential Dumping   | NTDS.dit acquisition via ntdsutil IFM      | T1003.003            | Domain credential theft                         |
| Surveillance Access  | Kerberos.io CCTV platform access           | T1083 / Collection   | Intelligence gathering                          |
| Collection           | Shipment files + CCTV footage              | T1213, T1005         | Data collection                                 |
| Exfiltration         | ManifestSync.ps1 uploads ZIP archives      | T1041                | Exfiltration over C2 channel                    |
| Command & Control    | Havoc C2 -> login.cargo-review.com          | T1071.001            | Encrypted web-based C2                          |

## Conclusion

The investigation determined that the compromise of the Global Freight UA environment began with a targeted phishing email containing a password-protected archive, `CargoPortalReview.zip`. After the recipient opened the archive and executed a malicious macro-enabled document, embedded VBA code launched PowerShell and deployed a secondary payload (`svc.exe`) onto the victim workstation (`GFUA-WKS01`).

Analysis of the payload confirmed that it was a Havoc Demon command-and-control agent configured to communicate with attacker-controlled infrastructure at `login.cargo-review.com`. Following successful execution, the attacker established persistence through registry run keys and scheduled tasks, enabling long-term access to compromised systems.

The attacker then conducted extensive reconnaissance to identify network resources, security controls, and potential targets for lateral movement. Using SMB-based file transfers and additional persistence mechanisms, the malware was propagated across multiple systems, including `GFUA-WKS02`, `GFUA-FS01`, `GFUA-MSSQL`, and `GFUA-DC01`.

Further investigation revealed that the attacker abused a vulnerable Active Directory Certificate Services (AD CS) certificate template (`RemoteAccessUsers`) to obtain a certificate for another user account. This allowed certificate-based authentication and facilitated privilege escalation within the domain. The attacker subsequently accessed the Domain Controller and leveraged ntdsutil `IFM` functionality to create an offline copy of the Active Directory database, providing access to domain credential material.

The intrusion extended beyond traditional IT assets, with evidence showing unauthorized access to the organization's CCTV infrastructure through the Kerberos.io surveillance platform. The attacker collected shipment-related data, surveillance footage, and Active Directory artifacts before staging the data for exfiltration.

Finally, analysis of PowerShell scripts and network activity revealed a dedicated exfiltration workflow masquerading as a backup service. Sensitive data was compressed, staged locally, and uploaded to attacker-controlled infrastructure via HTTP. SRUM network usage records further confirmed significant outbound data transfers associated with the malware during the intrusion period.

Overall, the attack demonstrates a well-structured intrusion lifecycle involving spearphishing, malicious document execution, command-and-control communications, persistence, reconnaissance, lateral movement, AD CS abuse, credential theft, surveillance access, data collection, and exfiltration. The observed techniques closely align with publicly documented tradecraft associated with APT28-style operations, where long-term access, credential abuse, intelligence gathering, and theft of sensitive organizational data are primary objectives.

A huge shoutout to the team behind [@XINTRA](https://www.xintra.org/) for creating a lab this detailed. Every log felt authentic, every artifact useful, and every pivot led to something meaningful. Massive thanks to all the analysts, red teamers, and reverse engineers who continue to raise the bar in adversary emulation and detection.

## 📬 Let’s Connect

If you have any feedback on my analysis, methodology, or investigative approach to this lab, I’d love to hear from you. Whether it’s suggestions for improving my process, alternative hunting techniques, or better ways to structure the investigation feel free to reach out!

You can find me on Discord at **@m3r1.t** — always happy to connect with fellow analysts and learn from different perspectives. 🙌

<img src="/assets/img/gfuc.png" alt="" />