---
title: "A Deep Dive Into Donex Ransomware [Part 2]"
date: 2025-04-18T15:08:12+03:00
slug: 2025-04-18-a-deep-dive-into-donex-ransomware-part-2
type: posts
draft: false
katex: false
summary: '[Part 2] In this series of posts we dive into the internals of the Donex Ransomware. This series serves mostly as notes to keep track of my findings. I also record the entire analysis process and upload a series of videos on my YouTube channel. More info inside the post :)'
categories:
  - projects
  - malware-analysis
tags:
  - malware-analysis
  - reverse-engineering
  - real-world
---

{{< toc >}}

[Here](https://rasti37.github.io/posts/2025-04-08-a-deep-dive-into-donex-ransomware-part-1) you can find part 1 of my Donex Ransomware Analysis blog post series.

# Introduction

In case you are interested in a more detail analysis, I am also recording my analysis process and uploading the videos in my YouTube channel. You can find the playlist [here](https://www.youtube.com/playlist?list=PLTB_YxFt6y5NLTaxytTa70E7Tvh4KaoCV).

<div style='color: orange'><i><b>WARNING!</b> <u>It's highly recommended to work in an isolated virtual machine without internet connection as the malware is 100% real. Running it on your host will harm your files.</u></i></div>

# Part 1 Checkpoint

This is how our decompilation looks like from the first part.

![](ida_ransomware_init_part_1.png)

We have a good idea of what the malware does so far but we still have to deal with the three last mysterious functions, namely `0x4014d0`, `0x401a30` and `0x4033f0`. Since we love cryptography (at least I do), we expect to find the crypto-related thingies in there so let's get into it.

# `sub_4014d0` (Random 16-byte key Generation)

Let's isolate the part of the code that we will analyze.

```c
BOOL __usercall sub_4014D0@<eax>(HCRYPTPROV a1@<ebp>, signed int a2)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  v13[1] = a1;
  v13[2] = retaddr;
  if ( CryptAcquireContextA(v13, 0, 0, 1u, 0)
    || GetLastError() != 0x80090016
    || (result = CryptAcquireContextA(v13, 0, 0, 1u, 8u)) )
  {
    v3 = malloc(a2);
    memset(v3, 0, a2);
    if ( CryptGenRandom(v13[0], a2, v3) )
    {
      v4 = 0;
      if ( a2 > 0 )
      {
        if ( a2 >= 8 && dword_439E74 >= 2 )
        {
          // ... REDACTED ...
```

The redacted part performs just a bunch of arbitrary numerical operations such as additions, shuffles, XORs etc.

As in every situation that we deal with with the Windows API, we will embrace [https://learn.microsoft.com/en-us/windows/win32/api/](https://learn.microsoft.com/en-us/windows/win32/api/) - our home sweet home. Looking at the documentation while reverse engineering, helps us label function arguments which significantly helps in our understanding of how the program operates.

From the documentation of the (deprecated) function [`CryptAquireContextA`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta), we deduce that the type of `v13` should be `HCRYPTPROV *` so we can change its type in IDA by pressing `Y`. Then, the penultimate argument, which corresponds to `dwProvType`, has the value `0x01`. [Here](https://learn.microsoft.com/en-us/windows/win32/SecCrypto/cryptographic-provider-types) you can find a list of all the available cryptographic provider types. But `0x01` is quite useless to us, we need to find the macro name corresponding to that value. We can click on `0x01` and press `M`. This will show us a list of defined enums and macros inside IDA. We search for `PROV_` and we find that `0x01` corresponds to `PROV_RSA_FULL`.

![](ida_prov_enums.png)

Similarly, we find that the error code `0x80090016` corresponds to `NTE_BAD_KEYSET`. Moreover, the last argument of the next call to `CryptAquireContextA`, which corresponds to `dwFlags` has the value `0x08`. Following a similar approach, we find that this flag value corresponds to `CRYPT_NEWKEYSET`.

Our next API function is `CryptGenRandom`. As the name implies, this function generates random bytes of given length and stores them into a buffer. From the docs, we can rename the arguments as follows:

```c
CryptGenRandom(hProv, dwLen, pbBuffer)
```

The argument of `sub_4014d0` is `0x10` which turns out to be `dwLen`. From that, we understand that a random 16-byte string is generated and stored in `pbBuffer`. Given that this is a ransomware, we can suspect that this is a symmetric encryption key. This key is then furtherly processed and is finally returned from this function.
Honestly, I really don't know why the malware authors decided to process the key and not just use a plain 16-byte string as the key. This additional process adds nothing to the security of the key.

Anyways, let's rename `sub_4014d0` to `generate_random_16byte_key`.

# `sub_401a30` (Figuring out the cryptographic library)

Chaos begins to emerge...

This function appears to be part of some library that does cryptographic thingies. Reverse engineering such libraries can be extremely painful. For example, implementing RSA-2048 encryption in python can be trivially implemented as `c = pow(m, e, n)`. However, in C, there are no built-in data types to support such large numbers, so we need to build custom data types. Usually, these data types are arrays of specific sized words. For instance, a 2048-bit number could be represented as an array of 128 16-bit words. Implementing mathematical operations, such as modular exponentiation, using these custom data types is really, really ... messy.

I didn't even attempt to reverse engineer this function and quickly made the educated guess that the malware authors didn't implement their own crypto and used some open source cryptographic library. To find this library, we will follow the same approach as for the XML library in part 1.

In `sub_401a30`, we see the following call:

```c
sub_4089C0(v15, sub_4082D0, v14, "rsa_encrypt", 0xBu);
```

This is poggers for two reasons:

- We learned that RSA encryption is involved.
- We know a string literal that might prove significant for figuring out the cryptographic library.

## Vibe search prompt creating

Additionally, the ultimate key for successfully finding what we are looking for, is the search prompt that we use (yes, prompts were important before the LLM-era too).

For our case, the prompt `"rsa_encrypt" in:github filetype:c` would be a good start. Unfortunately, this is quite a short string and pretty common among several libraries, such as polarssl, openssl, mbedtls and others.

A good idea would be to search for longer strings which are more unlikely to appear in multiple libraries, for example `pbeWithSHAAnd3-KeyTripleDES-CBC`. With this prompt, the search returns only three results:

![](mbedtls-g-results.png)

> Note that the second result is part of a minimalistic fork of the [original](https://github.com/Mbed-TLS/mbedtls) mbedtls repository.

We found a strong candidate for our library and that is `mbedtls`. Navigating the library's source code and by looking at specific strings like [these](https://github.com/Mbed-TLS/mbedtls/blob/master/library/oid.c#L894) are indicators that our finding is correct.

![](ida-mbedtls-structs.png)

The data appear adjacent, as in the original source code.

Great! We found the library, let's see if we can find any references to the string `rsa_encrypt`. It turns out that it is referenced in the file [`programs/pkey/rsa_encrypt.c`](https://github.com/Mbed-TLS/mbedtls/blob/master/programs/pkey/rsa_encrypt.c#L46).

The `program` folder contains some example use cases to help users use the mbedtls API and looks like the function we are analyzing is ... heavily influenced by this specific program

Library source code:

```c
const char *pers = "rsa_encrypt";

// REDACTED ...

mbedtls_mpi_init(&N); mbedtls_mpi_init(&E);
mbedtls_rsa_init(&rsa);
mbedtls_ctr_drbg_init(&ctr_drbg);
mbedtls_entropy_init(&entropy);

ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                            &entropy, (const unsigned char *) pers,
                            strlen(pers));
```

IDA decompilation:

```c
sub_406AD0(v17);
sub_406AD0(v18);
sub_407C60(v16);
sub_408770(v15);
sub_408430(v14);
sub_4089C0(v15, sub_4082D0, v14, "rsa_encrypt", 0xBu);
```

I don't know about you but these two code snippets look identical to me. Eureka!😄

<div style='display: flex; gap: 3em; justify-content: center;'>
  <a href="https://emoji.gg/emoji/Poggers"><img src="https://cdn3.emoji.gg/emojis/Poggers.png" width="64px" height="64px" alt="Poggers"></a>
  <a href="https://emoji.gg/emoji/Poggers"><img src="https://cdn3.emoji.gg/emojis/Poggers.png" width="64px" height="64px" alt="Poggers"></a>
  <a href="https://emoji.gg/emoji/Poggers"><img src="https://cdn3.emoji.gg/emojis/Poggers.png" width="64px" height="64px" alt="Poggers"></a>
</div>

We can go ahead and carefully rename the variables and the symbols in our decompilation until the result looks identical to the original. Then the function should look as follows:

```c
void *__cdecl sub_401A30(void *random_16byte_key, size_t key_length)
{  
  // REDACTED ...
  
  mbedtls_mpi_init(N);
  mbedtls_mpi_init(E);
  mbedtls_rsa_init(rsa_ctxt);
  mbedtls_ctr_drbg_init(ctr_drbg);
  mbedtls_entropy_init(entropy);
  mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, "rsa_encrypt", 0xBu);
  v4 = sub_402500(&Block);
  
  // REDACTED...
  
  mbedtls_mpi_read_file(N, 0x10u, v22);
  mbedtls_mpi_read_file(E, 0x10u, v10);
  mbedtls_rsa_import(rsa_ctxt, N, 0, 0, 0, E);
  encrypted_random_16byte_key = malloc(0x200u);
  memset(encrypted_random_16byte_key, 0, 0x200u);
  mbedtls_rsa_rsaes_pkcs1_v15_encrypt(
    rsa_ctxt,
    mbedtls_ctr_drbg_random,
    ctr_drbg,
    key_length,
    random_16byte_key,
    encrypted_random_16byte_key);
  return encrypted_random_16byte_key;
}
```

However, there is still one function not defined in mbedtls and looks donex-specific; that is `sub_402500`.

## `sub_402500` (Extracting the RSA public key from the malware's overlay)

For some reason, this function is unnecessarily verbose, while all it does is:

- The malware opens itself.
- Reads the data and stores them into a buffer.
- Returns a specific offset inside this buffer.

One can debug this piece of code inside a VM or do the arithmetic by hand using any hex editor, only to find out that:

```c
v9 = *a1 + *(*a1 + 60);
return *a1 + *(v9 + *(v9 + 20) + 40 * *(v9 + 6)) + *(v9 + *(v9 + 20) + 40 * *(v9 + 6) + 4);
```

returns the offset `0x37e00`. At this offset, there are some hex data defined.

It's a good exercise to try and figure out how this value is derived but here is my reasoning:

Since a PE file is read, we know that position `0x00` points to the `IMAGE_DOS_HEADER` and that position `0x60` points to the `IMAGE_NT_HEADERS`. Therefore we can change the type of these variables and then the decompilation makes much more sense.

```c
nt_headers = (*&a1->e_magic + *(*&a1->e_magic + 60));
return *&a1->e_magic                                       
        + *(&nt_headers->Signature + 40 * nt_headers->FileHeader.NumberOfSections + nt_headers->FileHeader.SizeOfOptionalHeader)               // 0x110 + 40 * 0x05 + 0xe0 = 0x2b8
        + *(&nt_headers->FileHeader.Machine + 40 * nt_headers->FileHeader.NumberOfSections + nt_headers->FileHeader.SizeOfOptionalHeader);   // 0x114 + 40 * 0x05 + 0xe0 = 0x2bc
```

This can be translated to:

```
*(0x00 + *(0x110 + 40 * 0x05 + 0xe0) + *(0x114 + 40 * 0x05 + 0xe0))
```

or equivalently:

```
*(0x00 + *(0x02b8) + *(0x02bc)) = *(0x00001c00 + 0x00036200) = *(0x37e00)
```

## Converting the overlay data to an RSA public key

Back to `sub_401A30`, after the call to `sub_402500`, there are the following lines:

```c
v4 = sub_402500(&Block);
v5 = v20;
qmemcpy(v2, v4, 0x200u);
```

It looks like it copies `0x200 = 512` bytes from this offset and copies it to `v2`. At this point, knowing that RSA is involved in the ransomware, we are pretty sure that this is the public RSA-4096 modulus `N`. For completeness (and have some impact on the google search indexing algorithm), the modulus is:

```
E3958800A4EE74BF5983967E3C658693CA93777EB8CA79FD724F6E6F71CD4724FFCD0F244AEBE33B87CC9F453878AB0C2DD69406C8ADFACE7AF9FAE46A37B5E5FC835DB3AE3F2261CD768F55CE15F327E6DB6142830A6CF5998143330268CFC7155E3B1B0161BA109403FDFA3D61A03AD24ED7F2B41E8A0BAE74A8C938F97B648546CE3EC0AD8B4115A156D568EE499B0D6411B0F9BC6E5087D062E3D541B3FE0B950412C399276EB0EF4D39743AE8411B6B42DBBC5694245816AC1BF99E5A1B1FC3870213ECA845807D5DF81EB07AC9F76894E31B89A2640FA40858CDEFD2B951B40927B64FC1A364FCE781DF4D90EB8F64DC8D4099A233EB3D791508809289
```

Then, the public exponent `E` lies, which is the standard value `0x010001` and finally, there is a hex extension that the malware appends to all the encrypted files, that is `f58A66B51`.

Having figured out all this, let's summarize what `sub_401A30` does.

- Initializes the rsa and the entropy context along with some other stuff required for encrypting with RSA.
- Extracts the RSA public key from the malware's overlay data and converts them from hex to mbedtls' data type `mpi`.
- It encrypts the 16-byte symmetric key generated from `sub_4014d0` using PKCS #1 v1.5 RSA-4096.

Therefore, let's rename `sub_401A30` to `rsa_encrypt_random_16byte_key` and `sub_402500` to `read_public_key_from_self`.

Moving on...

# `sub_4033f0` (Setting the default icon for encrypted files)

After the analysis of the previous function, this one should feel like a breeze.

Most symbols and variable names are already there so it's pretty straight forward to understand that this function, extracts the data from the `ico` XML tag, base64-decodes them and writes them to the local file `C:\ProgramData\icon.ico`.

This is deduced by the following snippet:

```c
v0 = fopen("C:\\ProgramData\\icon.ico", "wb");
Element = mxmlFindElement(xml_node_tree, xml_node_tree, "ico", 0, 0, 1);
element_data = mxml_extract_element_data(Element);
sub_408A50(0, 0, &ElementCount, element_data, strlen(element_data));
v3 = malloc_wrapper(ElementCount);
sub_408A50(v3, ElementCount, &ElementCount, element_data, strlen(element_data));
fwrite(v3, 1u, ElementCount, v0);
fclose(v0);
```

Since the data in `config.xml` are base64-encoded, we make an educated guess that `sub_408A50` does the base64 decoding. It calls it twice because the first time it needs to determine the size of the decoded data so that it can allocate a proper buffer to store them into. The data are actually stored in `v3` in the second function call.

Finally, there are some registry keys being set that do the following:

- Set the string `.f58A66B51` as the extension for any encrypted file
- Set `icon.ico` as the default icon for the encrypted files.

Let's rename `sub_4033f0` to `set_default_icon_and_post_enc_extension`.

That's all dudes and dudettes, see ya on the next part🙂