---
title: Uncovering Time Stomping in Windows A Deep Dive into Anti-Forensics with NTFS
date: 2024-06-31 12:00:00
categories: [DFIR]
tags: [dfir]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/mftimage.png
  lqip:
  alt: Uncovering Time Stomping in Windows A Deep Dive into Anti-Forensics with NTFS
---

In the world of digital forensics, attackers are constantly trying to cover their tracks—and one subtle but powerful method they use is time stomping. It’s an anti-forensic technique designed to manipulate file timestamps, hiding the true timeline of malicious activity. But thanks to the structure of the NTFS file system, we as analysts can still find traces of deception—if we know where to look.

## Why Attackers Hide in System Folders

One of the most common places attackers try to hide malware is in the `C:\Windows\System32` folder or similar system directories. These locations are filled with legitimate binaries and DLLs that Windows relies on. Dropping malware in here helps it blend into the noise.

But this strategy has a weak point: file modification dates. Most legitimate files in this folder were last modified when Windows was installed or updated. So if a malicious file was added recently, it sticks out like a sore thumb—and that's exactly what analysts are trained to spot.

## What is Time Stomping?

To prevent detection, attackers change the timestamps of the malicious file—a technique known as time stomping. This involves altering the file’s creation, modification, and access timestamps to mimic legitimate system files.

This can be done easily in PowerShell using Windows API methods like this:

```powershell
$path = "C:\Windows\System32\mimikatz.exe"
(Get-Item $path).CreationTime = '01/01/2020 12:00:00'
(Get-Item $path).LastWriteTime = '01/01/2020 12:00:00'
(Get-Item $path).LastAccessTime = '01/01/2020 12:00:00'
```

With just a few lines of code, the file now looks like it's been there for years—even if it was dropped on 2025.

In the first image below, we observe a suspicious file, mimikatz.exe, placed in the `C:\Windows\System32` directory. Its Date Modified is `31/03/2025 14:50` and Date Created is `31/03/2025 14:09`. 

<img src="/assets/img/mft1.png" alt="" />

In the second part of the screenshot below, we see the same file after a time stomping operation has been performed using PowerShell. Now, both Date Modified and Date Created are set to `01/01/2020 12:00`, which gives the impression that the file has been there for years.

<img src="/assets/img/mft2.png" alt="" />

## The NTFS Advantage for Forensic Analysts

Here’s where NTFS (New Technology File System) gives us the upper hand.

NTFS stores multiple sets of timestamps across different attributes. These are the main ones to know:

- `$STANDARD_INFORMATION` – Contains the timestamps used by Windows Explorer and most standard tools. This is what attackers usually modify.

- `$FILE_NAME` – Contains a second, independent set of timestamps associated with the file name. File name time-stamping is harder to tamper with, as it’s not affected by typical Windows API calls.

Even if an attacker changes the `$STANDARD_INFORMATION` timestamps, they usually leave behind discrepancies in the `$STANDARD_INFORMATION` attribute.

## Using the Master File Table (MFT) to Detect Time Stomping

The Master File Table (MFT) is a core structure in NTFS that tracks every file and folder on the volume. Each file has an MFT entry that contains metadata including both `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps.

Here’s a practical approach to detect time stomping:

**#1 Extract the MFT from the target system using `Kape` tool**

<img src="/assets/img/mft.png" alt="" />

**#2 Use a tool like `MFTECmd` by Eric Zimmerman to parse MFT entries.and export a timeline by converting the MFT to a bodyfile using `MFTECmd --body`.**

```powershell
MFTECmd.exe -f "C:\Users\Chamindu\Desktop\MFT\C\$MFT" --body C:\Users\Chamindu\Desktop\MFT\C --bodyf mft.body --blf --bdl C
```

<img src="/assets/img/mft-2.png" alt="" />

**#3 Analyze the file of interest (e.g., a suspicious mimiktaz.exe) and compare its timestamps.**

<img src="/assets/img/mft-3.png" alt="" />

## MFT Analysis with MFTECmd

The parsed output of MFTECmd for a suspicious file. and visible differences between `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps.

<img src="/assets/img/mft-5.png" alt="" />

```powershell
MFTECmd.exe -f "C:\Users\Chamindu\Desktop\MFT\C\$MFT" --de 102073
```

<img src="/assets/img/mft-4.png" alt="" />

Any indicators like zeroed microseconds in the timestamps (e.g., `2020-01-01 06:30:00.0000000`), which hint that they were modified via the Windows API.

## Case Example: Timestamp Mismatch Revealing the Truth

Let’s say you’ve collected the `MFT` and are analyzing a suspicious binary named `mimiktaz.exe`. Here's what you observe:

<img src="/assets/img/mft-4.png" alt="" />

- `STANDARD INFORMATION` timestamps show `2020-01-01 06:30:00.0000000`

- `FILE NAME` timestamps show `2025-03-31 09:19:46.7950679`

The microseconds in `$FILE_NAME` look natural, while the `$STANDARD_INFORMATION` timestamps are all rounded. This tells us that someone manually altered the timestamp using a limited API.

👉 The mismatch between these two attributes is a key indicator of anti-forensic tampering.


> This is important: The Windows API used in most time stomping techniques doesn’t support setting precise microsecond values, so the result often looks like `2020-01-01 12:00:00.0000000`.
In real-world scenarios, NTFS-generated timestamps almost never have all-zero microseconds. This makes the appearance of rounded timestamps a strong indicator of manual manipulation, pointing to possible time stomping activity.
{: .prompt-info }

## Conclusion: Time Stomping Leaves Clues
Time stomping is a clever way for attackers to hide in plain sight. But they often overlook the redundant timestamp storage in NTFS. By analyzing the MFT and comparing multiple timestamp sources, forensic analysts can detect even subtle manipulations.

### TL;DR
- Attackers drop malware in system folders and use time stomping to make it look old.
- NTFS stores multiple timestamp attributes some of which are harder to modify.
- Tools like `MFTECmd` can reveal timestamp mismatches that point to tampering.
- Rounded timestamps with all **zeros = suspicious**.
- Always compare `$STANDARD_INFORMATION` vs `$FILE_NAME`!

If you're doing a forensic investigation on NTFS systems, don't trust timestamps at face value. Dig deeper—and you'll often find the truth hidden in plain sight.

A skilled attacker can manipulate timestamps—but NTFS records the truth in multiple places. As analysts, it's our job to ask: “Does this timeline make sense?” and dig until we’re sure.
