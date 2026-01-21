---
title: 'asn1template - Edition ASN.1 sans douleur'
author: 'William Robinet (Conostix S.A.) - *https://github.com/wllm-rbnt/asn1template*'
patat:
    wrap: true
    margins:
        left: auto
        right: auto
        top: auto
    transition:
        type: slideLeft
        duration: 0.2
geometry: "left=1cm,right=1cm,top=1cm,bottom=1cm"
output: pdf_document
...

**Unlock Your Brain, Harden Your System 2024 - Brest**

**asn1template - Edition ASN.1 sans douleur**

William Robinet (Conostix S.A.) - 2024-11-09

@wr@infosec.exchange - willi@mrobi.net

---

<!--config:
margins:
    left: 10
    right: 10
-->

# A TLS/SSL certificate is an encoded ASN.1 structure

```bash
$ openssl x509 -in www.unlockyourbrain.bzh.der -inform der -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            03:8a:fb:a3:69:5d:18:e6:c8:eb:49:ea:ce:74:9f:ac:fb:21
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Let\'s Encrypt, CN = R10
        Validity
            Not Before: Sep 25 14:32:29 2024 GMT
            Not After : Dec 24 14:32:28 2024 GMT
        Subject: CN = front-webvps.diateam.net
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:bb:76:b4:97:9b:8d:ef:7a:59:93:56:69:8f:20:
[...]
            X509v3 Subject Alternative Name: 
                DNS:2019.unlockyourbrain.bzh, DNS:2020.unlockyourbrain.bzh, [...] DNS:www2.bluecyforce.com
[...]
```
---

<!--config:
margins:
    left: 10
    right: 10
-->

# DER is binary T(ype) L(ength) V(alue) encoding for ASN.1 (1/2)

```bash
$ openssl asn1parse -in www.unlockyourbrain.bzh.der -inform D -i
    0:d=0  hl=4 l=1898 cons: SEQUENCE          
    4:d=1  hl=4 l=1618 cons:  SEQUENCE          
    8:d=2  hl=2 l=   3 cons:   cont [ 0 ]        
   10:d=3  hl=2 l=   1 prim:    INTEGER           :02
   13:d=2  hl=2 l=  18 prim:   INTEGER           :038AFBA3695D18E6C8EB49EACE749FACFB21
   33:d=2  hl=2 l=  13 cons:   SEQUENCE          
   35:d=3  hl=2 l=   9 prim:    OBJECT            :sha256WithRSAEncryption
   46:d=3  hl=2 l=   0 prim:    NULL              
   48:d=2  hl=2 l=  51 cons:   SEQUENCE          
   50:d=3  hl=2 l=  11 cons:    SET               
   52:d=4  hl=2 l=   9 cons:     SEQUENCE          
   54:d=5  hl=2 l=   3 prim:      OBJECT            :countryName
   59:d=5  hl=2 l=   2 prim:      PRINTABLESTRING   :US
   63:d=3  hl=2 l=  22 cons:    SET               
   65:d=4  hl=2 l=  20 cons:     SEQUENCE          
   67:d=5  hl=2 l=   3 prim:      OBJECT            :organizationName
   72:d=5  hl=2 l=  13 prim:      PRINTABLESTRING   :Let´s Encrypt
   87:d=3  hl=2 l=  12 cons:    SET               
   89:d=4  hl=2 l=  10 cons:     SEQUENCE          
   91:d=5  hl=2 l=   3 prim:      OBJECT            :commonName
   96:d=5  hl=2 l=   3 prim:      PRINTABLESTRING   :R10
  101:d=2  hl=2 l=  30 cons:   SEQUENCE          
  103:d=3  hl=2 l=  13 prim:    UTCTIME           :240925143229Z
  118:d=3  hl=2 l=  13 prim:    UTCTIME           :241224143228Z
[...]
```

---

<!--config:
margins:
    left: 10
    right: 10
-->

# DER is binary T(ype) L(ength) V(alue) encoding for ASN.1 (2/2)

```bash
$ hexdump -C www.unlockyourbrain.bzh.der 
00000000  30 82 07 6a 30 82 06 52  a0 03 02 01 02 02 12 03  |0..j0..R........|
00000010  8a fb a3 69 5d 18 e6 c8  eb 49 ea ce 74 9f ac fb  |...i]....I..t...|
00000020  21 30 0d 06 09 2a 86 48  86 f7 0d 01 01 0b 05 00  |!0...*.H........|
00000030  30 33 31 0b 30 09 06 03  55 04 06 13 02 55 53 31  |031.0...U....US1|
00000040  16 30 14 06 03 55 04 0a  13 0d 4c 65 74 27 73 20  |.0...U....Let´s |
00000050  45 6e 63 72 79 70 74 31  0c 30 0a 06 03 55 04 03  |Encrypt1.0...U..|
00000060  13 03 52 31 30 30 1e 17  0d 32 34 30 39 32 35 31  |..R100...2409251|
00000070  34 33 32 32 39 5a 17 0d  32 34 31 32 32 34 31 34  |43229Z..24122414|
00000080  33 32 32 38 5a 30 23 31  21 30 1f 06 03 55 04 03  |3228Z0#1!0...U..|
00000090  13 18 66 72 6f 6e 74 2d  77 65 62 76 70 73 2e 64  |..front-webvps.d|
000000a0  69 61 74 65 61 6d 2e 6e  65 74 30 82 02 22 30 0d  |iateam.net0.. 0.|
[...]
00000410  30 32 32 2e 75 6e 6c 6f  63 6b 79 6f 75 72 62 72  |022.unlockyourbr|
00000420  61 69 6e 2e 62 7a 68 82  18 32 30 32 33 2e 75 6e  |ain.bzh..2023.un|
00000430  6c 6f 63 6b 79 6f 75 72  62 72 61 69 6e 2e 62 7a  |lockyourbrain.bz|
00000440  68 82 0f 62 6c 75 65 63  79 66 6f 72 63 65 2e 63  |h..bluecyforce.c|
00000450  6f 6d 82 11 64 65 76 2e  62 72 65 69 7a 68 63 74  |om..dev.breizhct|
00000460  66 2e 63 6f 6d 82 0b 64  69 61 74 65 61 6d 2e 6e  |f.com..diateam.n|
00000470  65 74 82 18 66 72 6f 6e  74 2d 77 65 62 76 70 73  |et..front-webvps|
00000480  2e 64 69 61 74 65 61 6d  2e 6e 65 74 82 10 68 6e  |.diateam.net..hn|
00000490  73 2d 70 6c 61 74 66 6f  72 6d 2e 63 6f 6d 82 0b  |s-platform.com..|
[...]
```

---

<!--config:
margins:
    left: 10
    right: 10
-->

# PEM is a text encoding used for transporting binary data such as DER

```bash
$ cat www.unlockyourbrain.bzh.pem
-----BEGIN CERTIFICATE-----
MIIHajCCBlKgAwIBAgISA4r7o2ldGObI60nqznSfrPshMA0GCSqGSIb3DQEBCwUA
MDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQD
EwNSMTAwHhcNMjQwOTI1MTQzMjI5WhcNMjQxMjI0MTQzMjI4WjAjMSEwHwYDVQQD
Exhmcm9udC13ZWJ2cHMuZGlhdGVhbS5uZXQwggIiMA0GCSqGSIb3DQEBAQUAA4IC
DwAwggIKAoICAQC7drSXm43velmTVmmPIC5oClUvxNKwqFVSymsId9C4LFKqURxa
hVlqQqMxP1EqYjfWZzXT9bvZkfqiAKobhj4AVa3zbQYzoccQQDJOvkRhAgK9BOCk
[...]
62EgtmxIHgM5Pn1IiWen4Cw5WgHnoJ9FnhDs7xdNUu7Wt/KofhS3oFzWUVnxiegv
owGdbi13Mmeje9Riy67uMGFnzBsOwPyPR8vPhXn0bpZwy9cEZliMmyY4nyIxu48w
EyogD6o8sijU1JjBos9488f5c7x4Y6+rkNL7pkbdzxV2mOmVOeiTzrIotkOt5a4M
hMPfT0/chMiOyTeKJkzraOcRNR9qM22P2viz2/2IeVC8yG7US2MRTMOLJGo9k3OL
cPlmSHycMhkXTPx1gdcm7oPJl7LJ7QhElUtlq6pI
-----END CERTIFICATE-----
```
    
---

<!--config:
margins:
    left: 10
    right: 10
-->

# OpenSSL's ASN1\_generate_nconf(3) function

```bash
 $ man ASN1_generate_nconf
 NAME
        ASN1_generate_nconf, ASN1_generate_v3 - ASN1 string generation functions
 
 [...]
 DESCRIPTION
        These functions generate the ASN1 encoding of a string in an ASN1_TYPE structure.
 [...]
```

# Idea

    DER_file == ASN1_generate_nconf( **do_something_with_the_output** ( asn1parse( DER_file ) ) )

*ASN1\_generate_nconf* can be reached through the *-genconf* option of *openssl asn1parse*.

---

<!--config:
margins:
    left: 10
    right: 10
-->

# asn1template

*https://github.com/wllm-rbnt/asn1template*

The usage process:

- *openssl asn1parse* dumps the DER structure as text
- *asn1template* converts this textual description to OpenSSL configuration syntax
- *ASN1_generate_nconf(3)* generates a new DER structure (reachable through -genconf in asn1parse)

Easy exploitation of recent vulns:

- Infinite loop in BN\_mod\_sqrt() reachable when parsing certificates (CVE-2022-0778)
- Possible DoS translating ASN.1 object identifiers (CVE-2023-2650)

Bonus:

- Supports multi-root files (eSIM)

---

<!--config:
margins:
    left: 10
    right: 10
-->

# Demo

- Retrieve *www.unlockyourbrain.bzh* TLS certificate in cert.der:

```bash
$ echo | openssl s_client -connect www.unlockyourbrain.bzh:443 | openssl x509 -out cert.der -outform D
```

- Convert TLS certificate to a template:

```bash
$ asn1template.pl cert.der > cert.tpl
```
   
- Edit cert.tpl (optional)
- Generate (modified) certificate from template:
   
```bash
$ openssl asn1parse -genconf cert.tpl -i -out cert.tpl.der
```

- Visually compare original certificate against modified one:

```bash
$ diff -u cert.der cert.tpl.der
$ meld <(openssl asn1parse -in cert.der -inform D -i) <(openssl asn1parse -in cert.tpl.der -inform D -i)
```

---

<!--config:
margins:
    left: 10
    right: 10
-->

**Thanks for your attention !**

