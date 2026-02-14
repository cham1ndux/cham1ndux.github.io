---
title: Scattered Spider Uncaged - The AB Projekt Blue Investigation
date: 2026-02-14 00:00:00
categories: [DFIR]
tags: [dfir]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/ab.png
  lqip:
  alt: Scattered Spider Uncaged - The AB Projekt Blue Investigation
---


## THREAT ACTOR

### Scattered Spider

This lab simulates an incident inspired by Scattered Spider, a financially motivated and highly capable threat actor known for targeting U.S. and global organizations through advanced social engineering, SIM swapping, and abuse of remote access software. The group is notable for its use of legitimate IT tools, identity-centric initial access, and rapid privilege escalation.

Scattered Spider operates in a loosely affiliated structure and often leverages public breach data, MFA fatigue, and help desk impersonation to gain a foothold. Recent campaigns have focused on telecommunications, technology, and critical services, including ransomware deployment in partnership with ALPHV/BlackCat/Qilin/DragonForce operators.

Victims have included high-profile enterprises where attackers leveraged stolen identities, third-party IT access, and living-off-the-land binaries (LOLBins) to blend into enterprise environments while performing internal reconnaissance and data exfiltration.

- [Scattered Spider](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)
- [Muddled Libra Threat Assessment: Further-Reaching, Faster, More Impactful](https://unit42.paloaltonetworks.com/muddled-libra/)
- [CrowdStrike Services Observes SCATTERED SPIDER Escalate Attacks Across Industries](https://www.crowdstrike.com/en-us/blog/crowdstrike-services-observes-scattered-spider-escalate-attacks/)

## LAB DESCRIPTION

In this lab, you will investigate a multi-stage intrusion targeting AB Projekt Blue, a game development studio, where Scattered Spider actors leveraged social engineering, cloud-based persistence, credential theft, and covert data exfiltration to execute a full ransomware extortion campaign.

Participants will follow the attacker’s TTPs through the full kill chain:

-  Social Engineering & MFA Fatigue
- Credential Access using multiple OST
- Bring Your Own Vulnerable Driver (BYOVD)
- EDR Manipulation
- Custom Ransomware Binary
- Remote Monitoring & Management (RMM)

## SCOPING NOTE

AB Projekt Blue is a mid-sized European video game development studio known for several major RPG titles under development. In July 2025, cyber defenders and forensic investigators uncovered a multi-phase intrusion attributed to the financially motivated threat actor known as Scattered Spider (also tracked as UNC3944, Muddled Libra, Octo Tempest, and 0ktapus).

Scattered Spider is a financially motivated threat actor known for targeting SaaS-heavy organizations using sophisticated social engineering, MFA abuse, and cloud exploitation techniques to gain access, maintain persistence, and extort victims through data theft and ransomware.

As an incident responder assigned to this case, you noticed a sequence of high-fidelity alerts originating from user workstations and cloud services. Initial telemetry flagged suspicious login activity involving a corporate email account, followed by the registration of a new MFA method under unusual conditions.

Investigation includes:

- KAPE Packages
- RMMs Log Files & Artifacts
- Custom Ransomware Binary
- Emails (.PST)
- PowerShell Transcript Logs
- All logs are sent to an Elastic stack - Windows Event Logs, Azure Logs, M365 Logs

Note: The attack campaign spanned from July 20 to July 30, 2025

## NETWORK DIAGRAM

Below is an image of the infected part of the ABProjektBlue network.

![](https://storagepublic.xintra.org/public/i/20250819-045432/ABPROJEKIT.PNG)

## Phantom Entry Points

So we kicked off this investigation by loading Maya's email PST file into XstReader to see what's inside.

<img src="/assets/img/ab1.png" alt="" />

Right away, two suspicious emails jumped out from Maya's inbox — both from `IT-Security` sent just 4 minutes apart on `7/21/2025`.

<img src="/assets/img/ab2.png" alt="" />
<img src="/assets/img/ab3.png" alt="" />

Email 1 (1:29 AM) - vague social engineering lure, just asking Maya to `finalize some verification process` with no link yet.
Email 2 (1:33 AM) - the follow-up with the actual phishing URL dropped in:
`https://login.secureaccesonline.com/iLyXOozI`

Classic two-step phishing play first email builds context, second delivers the payload link. That domain `secureaccesonline.com` is clearly spoofed to mimic a legitimate security portal. And interestingly, we already saw this exact domain in a previous case SPF/DKIM passed because the attacker used Mailgun infrastructure.

<img src="/assets/img/ab4.png" alt="" />

So after pulling the headers out of XstReader, we could clearly see the sending IP was `141.193.32.19` routed through` m32-19.eu.mailgun.net`. The attacker used Mailgun's EU infrastructure. Sender is `itsecurity@secureaccesonline.com` delivered to `maya@abprojektblue.onmicrosoft.com`.
What caught our eye was that `SPF, DKIM, DMARC` all passed because the attacker properly configured the domain with Mailgun, so Microsoft let it through clean, straight to inbox.

Message-ID is `<20250721013314.e1743b0cb048aa19@secureaccesonline.com>` and the Return-Path shows standard Mailgun bounce tracking format, which confirms this was a deliberate campaign.

## Lurking Access

So jumping over to the logs, we can see that on `Jul 21, 2025 at 02:12:04 UTC`, IP `37.231.101.228` triggered a `User started security info registration` event under Maya's account. That's roughly 39 minutes after the phishing email landed in her inbox at 01:33 AM.

This tells us Maya clicked that link, entered her credentials, and the attacker wasted no time. They logged in and registered a new MFA authenticator app under her account, locking in persistent access to the environment.

<img src="/assets/img/ab5.png" alt="" />

So looking deeper into that log entry, we can see the attacker registered AppCodeOnly method with device ID `01661756-3f20-6603-957d-25ca160a4239`. This is a TOTP-based authenticator app, not a push notification method.

<img src="/assets/img/ab6.png" alt="" />

That's a smart move on their part. By choosing AppCodeOnly, they avoid sending any push alerts to Maya's real device, meaning she would have no idea someone else just added an MFA method to her account. This is very consistent with Scattered Spider's known TTPs, where they quietly register a silent authenticator to maintain long term persistence without triggering any suspicion.

So at this point the attacker has valid credentials plus their own MFA registered. They now own the account. Let's move forward and see what they actually did once they were inside.

So moving forward in the timeline, we can see the attacker started working with Azure CLI through cmd.exe. The commands being executed were az.cmd ssh config and az.cmd ssh vm, both consistently targeting resource group `RG-LAB-ABPB-WESTUS2-PROD` and VM `ehvr5d-ABPB-dev01`.

<img src="/assets/img/ab7.png" alt="" />

What's interesting here is the pattern. Starting from Jul 20 they were already running SSH config commands, then it picks up again heavily on Jul 22 and Jul 23. They were repeatedly generating `azure_ssh_config` files, which means they were setting up SSH access directly into the Azure VM through Azure CLI.

This confirms the attacker moved laterally from Maya's compromised account into the cloud infrastructure and established a reliable SSH tunnel into the production VM for persistent access.

So digging into the artifacts from ABPB-WKS03, we found the actual SSH keys the attacker generated. Inside `C:\Labs\Evidence\ABProjektBlue\Additional Artifacts\ABPB-WKS03\priya\az_ssh_config\RG-LAB-ABPB-WESTUS2-PROD-ehvr5d-ABPB-dev01\` there are three files, `id_rsa`, `id_rsa.pub`, and `id_rsa.pub-aadcert.pub`.

<img src="/assets/img/ab8.png" alt="" />

Opening up id_rsa.pub we can clearly see at the end of the key the comment `priya@ABPB-WKS03`. This tells us the SSH key pair was generated from the user priya's profile on workstation `ABPB-WKS03`, and was used to authenticate directly into the Azure VM `ehvr5d-ABPB-dev01`.
So the attacker wasn't just operating from Maya's account. They had moved laterally onto Priya's workstation as well and used her machine to establish the SSH tunnel into the production VM. The compromise is wider than we initially thought.

## Persistance

So now things get even more interesting. On `ABPB-WKS02` we can see the attacker created a backdoor local account named `Adminstrator` (notice the deliberate typo, missing one 'i') with password `P@ssw0rd` using `net user Adminstrator P@ssw0rd /add`.

<img src="/assets/img/ab9.png" alt="" />
<img src="/assets/img/ab10.png" alt="" />

Right after that they wasted no time adding it to three groups: `Administrators`, `Users`, and `Remote Desktop Users`. That last one is key because adding to Remote Desktop Users means they set up RDP access on this machine, giving them a persistent graphical remote access path into `ABPB-WKS02` anytime they want.

So at this point the attacker has full control over multiple machines in this environment and has left themselves multiple ways back in. Let's keep digging and see what else they did.

So while filtering Event ID 7045 for newly installed services, we spotted something very suspicious. A service named "killer" was installed on ABPB-WKS03 under the SYSTEM context, with the binary dropped in Priya's Downloads folder at `C:\Users\priya\Downloads\8e92cc393a7f6acda90fff42925c42d2082dad593740ae2698d597dca5d1e7fc.SYS`.

<img src="/assets/img/ab12.png" alt="" />

We took that SHA256 and ran it through our CTI platform and it came back as viragt64.sys, flagged 10/72 vendors on VirusTotal. 

<img src="/assets/img/ab13.png" alt="" />

This is a known vulnerable driver, and the service name `killer` is a big red flag because this is consistent with a Bring Your Own Vulnerable Driver (BYOVD) technique where attackers load a legitimate but vulnerable signed driver to kill EDR/AV processes running on the machine.

## Credential Alchemy

So while going through the PowerShell console history on `ABPB-WKS02` under dmitri's account, we spotted some very telling commands. The attacker first ran Get-LocalUser -Name "dmitri" and `whoami /user` to grab dmitri's SID, then immediately jumped into `SharpDPAPI`.

<img src="/assets/img/ab14.png" alt="" />

They ran `.\SharpDPAPI.exe triage` and `.\SharpDPAPI.exe system` to enumerate available DPAPI blobs, then went straight for a specific credential blob at `C:\Users\dmitri\AppData\Local\Microsoft\Credentials\5177A88B92A37B0457FDC29C9B553B3B` using the `blob /in:` flag to decrypt it directly.

This tells us the attacker was after dmitri's stored Windows credentials. SharpDPAPI is commonly used to decrypt browser saved passwords, Windows credential manager entries, and other DPAPI protected secrets without needing to dump LSASS. So they were harvesting credentials to move even further across the environment.

So digging deeper into the process logs on ABPB-WKS02, we can see the full SharpDPAPI command that was executed from the backdoor Adminstrator account's Downloads folder. The attacker ran:

`SharpDPAPI.exe masterkeys /sid:S-1-5-21-699825636-2524572522-1776751789-1000 /password:P@ssw0rd /target:C:\Users\dmitri\AppData\Roaming\Microsoft\Protect`

This is very clean. They used the Adminstrator account's known password `P@ssw0rd` combined with dmitri's full SID to decrypt the DPAPI masterkeys stored under dmitri's profile. Once they have those masterkeys, every DPAPI protected credential under dmitri's account is wide open.
So the attacker essentially used their own backdoor account as the key to unlock dmitri's credential store. Let's keep going and see what they pulled out of it.

So jumping over to the browser history analysis on `ABPB-WKS02`, we can see the attacker was actively searching for PPL bypass tools on `7/23/2025`. They searched for PPLBlade via Bing, landed on the GitHub repo `https://github.com/tastypepperoni/PPLBlade`, browsed around it, and then went straight to the releases page at `https://github.com/tastypepperoni/PPLBlade/releases/tag/v1.0` to grab the binary.

<img src="/assets/img/ab15.png" alt="" />

PPLBlade is a well known tool designed specifically to bypass Windows Protected Process Light and dump LSASS memory. Combined with the BYOVD driver they dropped earlier with viragt64.sys, this paints a very clear picture. They were building a full credential dumping chain, first kill the EDR with the vulnerable driver, then bypass PPL protection, then dump LSASS to harvest all credentials in memory.

`HackTool:Win32/DumpLsass.AA!dha` to this binary as threat signature.10:19 PMSo that confirms it. Windows Defender flagged `C:\Users\Adminstrator\Downloads\PPLBlade.exe` with the signature `HackTool:Win32/DumpLsass.AA!dha` on `ABPB-WKS02`. The binary was sitting right inside the backdoor Adminstrator account's Downloads folder, same place they dropped SharpDPAPI earlier.

<img src="/assets/img/ab16.png" alt="" />

## Encrypted Endgame

So shifting our focus over to ABPB-WKS03, we went through the contents of the Downloads folder and found multiple suspicious binaries sitting there. One that immediately caught our attention was `main.exe`.

<img src="/assets/img/ab17.png" alt="" />

So let's pop that binary open and run strings against it to see what's hiding inside. That should give us a good idea of whether this is the ransomware payload and potentially reveal any hardcoded C2 addresses, ransom note strings, file extension targets, or encryption related artifacts.

<img src="/assets/img/ab18.png" alt="" />

So running strings against main.exe gave us exactly what we were looking for. Right there in plaintext we can see the hardcoded ransom note content starting with `>>> YOUR NETWORK HAS BEEN COMPROMISED <<<` confirming this is without a doubt the ransomware payload.
What's really interesting is the exclusions list embedded inside the binary. The ransomware was configured to skip 12 directories including `C:\Windows`, `Azure Monitor Agent`, `Elastic Agent`, `Microsoft Monitoring Agent paths`, `Recycle Bin`, `System Volume Information`, `Recovery`, and `WER folders`. 

On the file side it excludes 8 specific filenames: `note.txt`, `log.log`, `AzureMonitorAgent.exe`, `Filebeat.exe`, `elastic-agent.exe`, `MicrosoftMonitoringAgent.exe`, `desktop.ini`, and `thumbs.db`.
It also skips 9 file extensions from encryption: `.exe`, `.dll`, `.sys`, `.log`, `.evtx`, `.txt`, `.pf`, `.tmp`, `and` `.temp`.

So while going through the Desktop on ABPB-WKS03, we found a file named notes.txt which turned out to be the ransom note dropped by the attacker. The note warned the victim not to attempt any file recovery or reach out to third parties.

<img src="/assets/img/ab19.png" alt="" />

The demand was `$5,000,000 USD` in Bitcoin with a 72 hour payment deadline. They also dropped a dark web negotiation portal link at `http://r3c0veryp4yment6zv6.onion` for the victim to make contact.

This lines up perfectly with the ransom note content we already found hardcoded inside `main.exe` earlier. At this point we have the full picture of this intrusion from the initial phishing email hitting Maya's inbox all the way through to ransomware deployment across the environment.

## Breaking Defenses

So continuing our investigation on `ABPB-WKS03`, Windows Defender flagged another malicious binary at `C:\Users\priya\Downloads\killer.exe` with the signature `HackTool:Win32/BackStab.A`.

<img src="/assets/img/ab20.png" alt="" />

BackStab is a well known tool specifically designed to kill EDR and security agent processes by abusing vulnerable drivers, which ties directly back to the `viragt64.sys` driver we found earlier installed as the "killer" service. The name of the binary itself, `killer.exe`, makes the intent pretty obvious.

So they had a full EDR killing chain set up on `ABPB-WKS03`: drop the vulnerable driver via the "killer" service, then use `BackStab` to leverage that driver and terminate any security processes protecting the machine. Let's keep going and see what came after they blinded the defenses.

So we can see the actual execution of `killer.exe` on `ABPB-WKS03` under priya's account. The command run was `killer.exe -n wazuh`, directly targeting the Wazuh security agent by name to terminate it.

<img src="/assets/img/ab21.png" alt="" />
<img src="/assets/img/ab22.png" alt="" />

Wazuh is an open source SIEM and EDR agent, so by killing it the attacker effectively blinded the entire security monitoring stack on that machine. No more log forwarding, no more process monitoring, no more alerts going out.

This confirms the sequence: drop viragt64.sys as the "killer" service to load the vulnerable driver, then use BackStab (killer.exe) to leverage that driver and terminate Wazuh specifically.

<img src="/assets/img/ab22.png" alt="" />

So another critical finding tied to this execution was the invocation of `SeLoadDriverPrivilege` by the malicious binary. This is one of the most dangerous Windows privileges you can have because it allows loading custom kernel-mode drivers directly into the Windows kernel.

<img src="/assets/img/ab23.png" alt="" />

This is exactly how the whole BYOVD chain worked on this machine. The attacker used `SeLoadDriverPrivilege` to load viragt64.sys into kernel space, giving killer.exe the ability to interact at the kernel level and forcefully terminate protected security processes like Wazuh that would otherwise be untouchable from userland.

At this point the attacker had full control, no EDR watching, credentials harvested, persistent access established across multiple machines. The environment was completely wide open for the final ransomware deployment.

## Scattered Portals

So pivoting over to ABPB-WKS01, we pulled the AnyDesk logs and found something very familiar. The log clearly shows Logged in from 37.231.101.228:26620 on relay `e80d2c46`, and that IP `37.231.101.228` is the exact same one we saw back when the attacker registered the rogue MFA authenticator under Maya's account.

<img src="/assets/img/ab24.png" alt="" />

This is a solid confirmation that we are tracking the same threat actor throughout this entire intrusion. They used AnyDesk as an additional remote access method routed through relay `e80d2c46` to avoid direct connections, landing on the internal address `10.183.3.12` on port `**7070`.
So the attacker had multiple remote access paths into the environment simultaneously: SSH tunnels into the Azure VM, RDP via the backdoor Adminstrator account, and now AnyDesk on ABPB-WKS01. They were making sure they had every possible way back in.

<img src="/assets/img/ab25.png" alt="" />

So looking deeper into the same AnyDesk log entry, we can pull out two more critical identifiers. The Client-ID of the attacker's machine is `1216418688` with a Client Fingerprint (FPR) of `b80684e1e6d2`, and the connection was re-used to client `b80684e1e6d2349b24e7137c197e5949df09cb0b`.

The FPR is particularly valuable here because unlike IP addresses that can change, the Client Fingerprint stays consistent across different victims and sessions. This means if this same attacker hits another organization using AnyDesk, that FPR `b80684e1e6d2` can be used to directly link the activity back to the same threat actor machine, making it a strong attribution indicator to share in threat intel reports.

So while going through the PowerShell transcripts on `ABPB-WKS02`, we spotted the attacker using Chocolatey to install ngrok via `C:\ProgramData\chocolatey\choco.exe` install ngrok under Process ID `9392`.

<img src="/assets/img/ab26.png" alt="" />

Using Chocolatey here is a smart move on their part. It's a legitimate Windows package manager so it blends in with normal admin activity and is less likely to trigger alerts compared to directly downloading a binary from the internet. ngrok then gives them an encrypted reverse tunnel out of the environment, creating yet another persistent external access channel that's difficult to block since it tunnels over standard HTTPS.

This is a well documented Scattered Spider TTP. They consistently abuse legitimate tools like Chocolatey and ngrok to maintain stealthy persistent access while avoiding detection.

So right after installing ngrok, we can see the attacker immediately authenticated it using `ngrok.exe config add-authtoken with the token 2uSsg9WbMZ7Vxwx9qbDdMQ4Ear7_5jEkcWxqLmYrEiZ8v3oe7` on `ABPB-WKS02`.

<img src="/assets/img/ab27.png" alt="" />

This authtoken ties the ngrok tunnel directly back to the attacker's ngrok account. That token is a solid IOC worth flagging, as it can be used to identify other infrastructure or sessions linked to the same ngrok account across different victim environments.

## Extraction Point

So moving into the exfiltration phase, we found `rclone v1.70.3` sitting in priya's Downloads folder on `ABPB-WKS03` at `C:\Users\priya\Downloads\rclone-v1.70.3-windows-amd64\rclone-v1.70.3-windows-amd64\rclone.exe`. What's immediately noticeable is that the other files in that folder like `rclone.1.ransomx`, `rclone.conf.ransomx`, and `README.html.ransomx` all carry the `.ransomx` extension, confirming the ransomware had already been through that directory.

<img src="/assets/img/ab29.png" alt="" />
<img src="/assets/img/ab28.png" alt="" />

To back this up, the DNS logs show a query to `downloads.rclone.org` at `2025-07-23 23:18:34` from Process ID 3864, confirming the attacker downloaded rclone directly onto the machine.

`rclone` is a command line cloud storage tool heavily abused by ransomware operators for bulk data exfiltration. The attacker used it to silently transfer data out of the environment to an external cloud destination before triggering the ransomware encryption. Classic double extortion setup, steal the data first, then encrypt.

So looking at the actual rclone execution logs on `ABPB-WKS03`, we can see exactly what the attacker was doing. They ran multiple rclone copy commands targeting `C:\users\priya\Code\cyberfunk.rar` and pushing it out to `do-sftp:/home/lootuser/loot` using both rclone.1 and rclone.conf config files.

<img src="/assets/img/ab29.png" alt="" />

The destination `do-sftp` strongly suggests they were exfiltrating to a DigitalOcean SFTP server with a user account literally named `lootuser`, dropping everything into a `/loot` directory. Pretty brazen naming convention.

<img src="/assets/img/ab30.png" alt="" />

We also caught them running `rclone.ex`e obscure `P@ssw0rd123!!!` twice, which is rclone's built-in command to encode a plaintext password for use in config files. This means their SFTP authentication password was `P@ssw0rd123!!!` before encoding.

So the full exfiltration picture is clear. They archived priya's Code directory into `cyberfunk.rar`, then used rclone over SFTP to push it out to their DigitalOcean server before triggering the ransomware encryption.

So pulling the network telemetry, we can see `rclone.exe` initiated an outbound TCP connection from `10.183.3.13` on `ABPB-WKS03` under priya's account to destination IP `206.189.13.43` over port 22 (SFTP). This is the attacker's C2 server where all the exfiltrated data was being pushed to.

<img src="/assets/img/ab31.png" alt="" />

So `206.189.13.43` is a solid IOC to add to the report. That's the confirmed exfiltration destination for `cyberfunk.rar` containing priya's Code directory. Let's go ahead and do a quick lookup on that IP to identify the hosting provider and any other context around

So during static analysis of rclone.exe pulled from `ABPB-WKS03`, we identified the binary's entry point address at `0x84c60`. 

<img src="/assets/img/ab32.png" alt="" />

This is useful for anyone doing deeper reverse engineering on this sample, as it gives us the exact offset to start tracing execution flow and understanding how the attacker may have modified or configured this build of rclone.

So shifting over to the SharePoint audit logs, we can see the attacker was hitting `https://abprojektblue.sharepoint.com/sites/CyberFunk/` and bulk downloading files from the `Engineering/Documentation` directories including `APIs`, `Architecture`, and Technical folders across both 2023 and 2025 content.

<img src="/assets/img/ab33.png" alt="" />

What gives them away immediately is the user-agent string `python-requests/2.31.0`. No legitimate user browses SharePoint with a raw Python requests library. This confirms the attacker was running a custom Python script, likely leveraging the Microsoft Graph API, to programmatically enumerate and bulk download the entire SharePoint site contents.

With 101 documents logged as FileDownloaded events, this was a systematic sweep of the company's engineering documentation. Combined with the rclone exfiltration we saw earlier, the attacker had a very structured double exfiltration approach, SharePoint data out via Python script and local files out via rclone over SFTP.

So digging into the AnyDesk artifacts on `ABPB-WKS02` under dmitri's profile, we found a `file_transfer_trace` log inside the `ad_f45e5af2_msi` folder. This trace file reveals the attacker used AnyDesk's clipboard file transfer feature to pull two files off the compromised machine during their remote session.

<img src="/assets/img/ab34.png" alt="" />

At 02:23 they downloaded `public.key` (32 B) and `main.exe` (3.32 MiB), then repeated the exact same transfer again at 02:26. The fact that they transferred `main.exe` through AnyDesk confirms this is how the ransomware binary was delivered and staged onto the machine, dropped directly via the AnyDesk clipboard transfer rather than downloading from an external URL, making it much harder to detect at the network level.

So while going through the RDP bitmap cache artifacts from ABPB-WKS02 under dmitri's Terminal Server Client profile, we processed the cache files through BMC-Tools which generated over 12,000 images in the output folder. After sorting by size we zeroed in on Cache0001.bin_collage and opened it up in Paint.

<img src="/assets/img/ab35.png" alt="" />

Right there in the reconstructed RDP session screenshot we can clearly see the project directory name ABProjektBlue displayed prominently in the File Explorer title bar and repository browser. This confirms the attacker was actively browsing through the internal development environment and code repositories during their RDP session, giving us a clear visual of exactly what they were looking at inside the compromised environment.

## Conclusion

So wrapping up this investigation, we started with a simple phishing email landing in Maya Sterling's inbox and ended up uncovering a full scale Scattered Spider intrusion across the entire ABProjektBlue environment.

The attack chain was very methodical. The threat actor sent a two-step phishing email from `itsecurity@secureaccesonline.com` via Mailgun infrastructure, bypassing all email authentication checks. Once Maya clicked the link and entered her credentials, the attacker immediately registered a silent TOTP-based MFA method under her account to lock in persistent access without raising any alerts.

From there they moved fast. They pivoted across multiple workstations, created a backdoor local account `Adminstrator` with RDP access on `ABPB-WKS02`, deployed the `viragt64.sys` vulnerable driver via a BYOVD attack, and used `BackStab` (killer.exe) to terminate Wazuh and blind the security monitoring stack.

For credential harvesting they used `SharpDPAPI` to decrypt DPAPI protected credentials from dmitri's profile and downloaded `PPLBlade` to dump LSASS memory. They also established multiple persistent remote access channels simultaneously including `AnyDesk`, `ngrok`, and SSH tunnels into the `Azure VM `on `RG-LAB-ABPB-WESTUS2-PROD`.

On the exfiltration side they ran a custom Python script to bulk download `101` documents from the CyberFunk SharePoint site and used `rclone` over SFTP to push `cyberfunk.rar` out to their C2 server at `206.189.13.43`. The ransomware binary `main.exe` along with `public.key` were deployed across machines via AnyDesk clipboard transfers.

The intrusion concluded with the deployment of ransomware across the environment, a ransom demand of `$5,000,000 USD` in Bitcoin within 72 hours, and a dark web negotiation portal at `http://r3c0veryp4yment6zv6.onion`. This was a well planned, multi-stage attack consistent with Scattered Spider's known TTPs, combining social engineering, living-off-the-land techniques, and ransomware partnership to maximize impact.

A huge shoutout to the team behind [@XINTRA](https://www.xintra.org/) for creating a lab this detailed. Every log felt authentic, every artifact useful, and every pivot led to something meaningful. Massive thanks to all the analysts, red teamers, and reverse engineers who continue to raise the bar in adversary emulation and detection.

To anyone out there digging into similar TTPs, stay curious and keep learning. Threat actors may be stealthy — but we’ve got grit, timestamps, and YARA.

## 📬 Let’s Connect

If you have any feedback on my analysis, methodology, or investigative approach to this lab, I’d love to hear from you. Whether it’s suggestions for improving my process, alternative hunting techniques, or better ways to structure the investigation — feel free to reach out!

You can find me on Discord at @m3r1.t — always happy to connect with fellow analysts and learn from different perspectives. 🙌

<img src="/assets/img/ab36.png" alt="" />
