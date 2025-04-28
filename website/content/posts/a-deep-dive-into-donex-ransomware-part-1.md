---
title: "A Deep Dive into Donex Ransomware [Part 1]"
date: 2025-04-08T11:25:59+03:00
slug: 2025-04-08-a-deep-dive-into-donex-ransomware-part-1
type: posts
draft: false
katex: false
summary: '[Part 1] In this series of posts we dive into the internals of the Donex Ransomware. This series serves mostly as notes to keep track of my findings. I also record the entire analysis process and upload a series of videos on my YouTube channel. More info inside the post :)'
categories:
  - projects
  - malware-analysis
tags:
  - malware-analysis
  - reverse-engineering
  - real-world
---

{{< toc >}}

[Here](https://rasti37.github.io/posts/2025-04-18-a-deep-dive-into-donex-ransomware-part-2) you can find part 2 of my Donex Ransomware Analysis blog post series.

# Introduction

I stumbled upon this cool [talk](https://cfp.recon.cx/recon2024/talk/LQ8B7H/) and learned about the existence of the Donex ransomware. I didn't want to spoil myself so I decided to do the analysis first and then watch the talk. The only thing I know is that it's possible to make a decryptor for this ransomware which really hyped me up and thought it's a good opportunity to sharpen my malware analysis skills and at the same time share my findings with all of you. I am also recording my analysis process and uploading the videos in my YouTube channel. You can find the playlist [here](https://www.youtube.com/playlist?list=PLTB_YxFt6y5NLTaxytTa70E7Tvh4KaoCV).

You can find and download the malware [sample](https://bazaar.abuse.ch/sample/0adde4246aaa9fb3964d1d6cf3c29b1b13074015b250eb8e5591339f92e1e3ca/) from Malware Bazaar.

<div style='color: orange'><i><b>WARNING!</b> <u>It's highly recommended to work in an isolated virtual machine without internet connection as the malware is 100% real. Running it on your host will harm your files.</u></i></div>

# Initial Analysis

- SHA256 Checksum: `0adde4246aaa9fb3964d1d6cf3c29b1b13074015b250eb8e5591339f92e1e3ca`
- CPU Architecture: 32-bit (x86)

# sub_4035C0 (main)

In the decompilation, we see the following two lines.

```c
WindowA = FindWindowA("ConsoleWindowClass", *argv); // *argv = argv[0]
ShowWindow(WindowA, SW_HIDE);
```

This is a common technique that the malwares use to operate in stealth.

It searches for the console window spawned by the malware executable and hides it. `argv[0]` corresponds to the first argument of the program which is the executable name.

# sub_4030D0 (Ransomware Initialization)

First, it creates a mutex with name "CheckMutex". If it already exists, it exits.

```c
if ( CreateMutexA(0, 1, "CheckMutex") && GetLastError() == ERROR_ALREADY_EXISTS )
{
    _loaddll(0);
    JUMPOUT(0x403338);
}
```

## Config Extraction

A huge encrypted blob is then decrypted with the key `0xA9`. The size of this blob is `0x21e7` bytes and it turns out to be an XML object with the malware configuration (authors being creative for real...).

```c
for ( i = 0; i < 0x21C0; i += 64 )
  {
    *&xml_blob[i] = _mm_xor_si128(XOR_KEY, *&xml_blob[i]);
    *&xml_blob[i + 16] = _mm_xor_si128(XOR_KEY, *&xml_blob[i + 16]);
    *&xml_blob[i + 32] = _mm_xor_si128(*&xml_blob[i + 32], XOR_KEY);
    *&xml_blob[i + 48] = _mm_xor_si128(XOR_KEY, *&xml_blob[i + 48]);
  }
  for ( ; i < 0x21E7; ++i )
    xml_blob[i] ^= 0xA9u;
```

From this code, we deduce that the decryption algoritmh is simple XOR.

Let's decrypt the first few bytes to verify our deductions.

```python
>>> from pwn import xor
>>> xor(b'\xa9', bytes.fromhex('9596D1C4C589DFCCDBDAC0C6C7948E98'))
b"<?xml version='1"
```

Bingo! Let's write a short python script to decrypt the XML configuration and dump it into a file.

```python
import pefile
from pwn import xor

pef = pefile.PE('0adde4246aaa9fb3964d1d6cf3c29b1b13074015b250eb8e5591339f92e1e3ca')
BLOB_SIZE = 0x21e7
encrypted_xml_blob = pef.sections[2].get_data()[:BLOB_SIZE]
xml_blob = xor(encrypted_xml_blob, b'\xa9')
open('config.xml', 'w').write(xml_blob.decode())
```

Here is a preview of the XML configuration:

```xml
<?xml version='1.0' encoding='UTF-8'?>
<root>
<white_extens>386;adv;ani;bat;bin;cab;cmd;com;...<REDACTED>...;key;hta;msi;pdb;search-ms</white_extens>
<white_files>bootmgr;autorun.inf;boot.ini;...<REDACTED>...;GDIPFONTCACHEV1.DAT;d3d9caps.dat</white_files>
<white_folders>$recycle.bin;config.msi;...<REDACTED>...;microsoft;appdata</white_folders>	
<kill_keep>sql;oracle;mysq;chrome;veeam;firefox;excel;msaccess;onenote;outlook;powerpnt;winword;wuauclt</kill_keep>
<services>vss;sql;svc$;memtas;mepocs;msexchange;sophos;veeam;backup;GxVss;GxBlr;GxFWD;GxCVD;GxCIMgr</services>
<black_db>ldf;mdf</black_db>
<encryption_thread>30</encryption_thread>
<walk_thread>15</walk_thread>
<local_disks>true</local_disks>
<network_shares>true</network_shares>
<kill_processes>true</kill_processes>
<kill_services>true</kill_services>
<shutdown_system>true</shutdown_system>
<delete_eventlogs>true</delete_eventlogs>	
<cmd>wmic shadowcopy delete /nointeractive</cmd>
<cmd>vssadmin Delete Shadows /All /Quiet</cmd>
<content>            !!! DoNex ransomware warning !!!

&gt;&gt;&gt;&gt; Your data are stolen and encrypted

The data will be published on TOR website if you do not pay the ransom 

...<REDACTED>...

&gt;&gt;&gt;&gt; Warning! If you do not pay the ransom we will attack your company repeatedly again!
</content>
<ico>AAABAAEAIEAAAAEAIACoEAAAF...<REDACTED>.../wAAf/+AB///wA////AP///4H/8=</ico>
</root>
```

You can view the entire file in my GitHub [repository](https://github.com/rasti37/malware-analysis/blob/main/Donex/config.xml).

Optionally, we can also extract the data from the `ico` XML element and base64-decode them to see the default icon that the ransomware sets for each encrypted file. You can also find this icon in my [repository](https://github.com/rasti37/malware-analysis/blob/main/Donex/icon.ico).

Then, the function `sub_410750` is called which calls `sub_410A10`. Searching online some of this function's strings, such as `"Unable to add value node of type %s to parent"`, we find out that this function is part of an open-source XML parsing library known as [`mxml`](https://github.com/sharpee/mxml). More specifically, this one is [`mxml_load_data`](https://github.com/michaelrsweet/mxml/blob/master/mxml-file.c#L805).

## Deleting the shadow copies

The function `sub_402DD0` gets the token of the current process and checks whether it belongs to the admins group. This is deduced from the subauthorities defined in the `AllocateAndInitializeSid` call. The subauthorities are the following:

- `0x20` -- Corresponds to the RID: `SECURITY_BUILTIN_DOMAIN_RID`.
- `0x220` -- Combination of RIDs: `0x200 | 0x20` which correspond to `DOMAIN_GROUP_RID_ADMINS | SECURITY_BUILTIN_DOMAIN_RID`.

We can find these values from the original [documentation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b9475e91-f00f-4c25-9117-a48e70584625).

If the token belongs to the admins group, it executes the following commands:

  ```
  cmd /c "wmic shadowcopy delete /nointeractive"
  ```
  
  ```
  cmd /c "vssadmin Delete Shadows /All /Quiet"
  ```
  
  These commands are commonly used by ransomware threat actors to delete the shadow copies in windows systems so that victims cannot restore their original files back from the shadow copies.

## Disabling and Reverting WoW64 File System Redirection

Let's analyze the following code snippet:

```c
ModuleHandleA = GetModuleHandleA("kernel32.dll");
IsWow64Process = GetProcAddress(ModuleHandleA, "IsWow64Process");
if ( !IsWow64Process || (CurrentProcess = GetCurrentProcess(), IsWow64Process(CurrentProcess, &j)) )
{
  if ( j )
    Wow64DisableWow64FsRedirection(&OldValue);
}
```

Definition from [Wikipedia](https://en.wikipedia.org/wiki/WoW64):
> WoW64 (Windows 32-bit on Windows 64-bit) is a subsystem of the Windows operating system capable of running 32-bit applications on 64-bit Windows.

In other words, `WoW64` is the reason why we can run 32-bit applications (such as this ransomware) in 64-bit Windows systems.

But what is file system redirection?

By default, WoW64 transparently redirects all the system calls made by 32-bit applications to the system folder `C:\Windows\SysWoW64` which contains 32-bit libraries and executables.

Calling `Wow64DisableWow64FsRedirection`, disables this file system redirection and as a result, the native System32 folder is used. This is mandatory for executing the shadow copy deletion as the malware needs to call the 64-bit `vssadmin` and `wmic` binaries. Once it's done, the redirection can be re-enabled using `Wow64RevertWow64FsRedirection`.

```c
v8 = GetModuleHandleA("kernel32.dll");
ProcAddress = GetProcAddress(v8, "IsWow64Process");
if ( !ProcAddress || (v10 = GetCurrentProcess(), ProcAddress(v10, &j)) )
{
  if ( j )
    Wow64RevertWow64FsRedirection(OldValue);
}
```

# Conclusion

That's all for the first post. In the next post we explore `sub_4014D0` as well as the next two initialization functions. Take care :)