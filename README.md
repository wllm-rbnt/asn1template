# ASN.1 templating

## Description

This tool takes a DER or PEM encoded ASN.1 structure and outputs the equivalent
textual description that can be edited and later be fed to OpenSSL's
```ASN1_generate_nconf(3)``` function in order to build the equivalent DER
encoded ASN.1 structure.
The code is written in Perl with minimal dependencies. No compilation required.

```
$ git clone https://github.com/wllm-rbnt/asn1template.git
$ cd asn1template
$ ./asn1template -h
Usage:
	./asn1template.pl [--help|-h] [--pem|-p] [--simple-labels|-s] [--multi-root|-m] <encoded_file>

Default input file format is DER, use --pem (or -p) option to switch to PEM
Use --multi-root (or -m) option to process multiple concatenated structures from a single input file
Use --simple-labels (or -s) option to use simple numeric labels
Use --help (or -h) to print this help message
```

Here is an example of usage. First, let's convert a PEM encoded certificate to
a textual representation supported by ```ASN1_generate_nconf(3)```. The
certificate we use in this example is a root CA certificate from Amazon. On
Debian, it belongs to the ```ca-certificates``` package.

```
$ ./asn1template.pl --pem /etc/ssl/certs/Amazon_Root_CA_3.pem | tee Amazon_Root_CA_3.tpl
asn1 = SEQUENCE:seq1@0-4-438
[seq1@0-4-438]
field2@4-4-347 = SEQUENCE:seq2@4-4-347
field3@355-2-10 = SEQUENCE:seq3@355-2-10
field4@367-2-73 = FORMAT:HEX,BITSTRING:3046022100E08592A317B78DF92B06A593AC1A98686172FAE1A1D0FB1C7860A64399C5B8C40221009C02EFF1949CB396F9EBC62AF8B62CFE3A901416D78C6324481CDF307DD5683B
[seq2@4-4-347]
field5@8-2-3 = IMPLICIT:0C,SEQUENCE:seq4@8-2-3
field6@13-2-19 = INTEGER:0x066C9FD5749736663F3B0B9AD9E89E7603F24A
field7@34-2-10 = SEQUENCE:seq5@34-2-10
field8@46-2-57 = SEQUENCE:seq6@46-2-57
field9@105-2-30 = SEQUENCE:seq7@105-2-30
field10@137-2-57 = SEQUENCE:seq8@137-2-57
field11@196-2-89 = SEQUENCE:seq9@196-2-89
field12@287-2-66 = IMPLICIT:3C,SEQUENCE:seq10@287-2-66
[seq4@8-2-3]
field13@10-2-1 = INTEGER:0x02
[seq5@34-2-10]
field14@36-2-8 = OBJECT:ecdsa-with-SHA256
[seq6@46-2-57]
field15@48-2-11 = SET:set11@48-2-11
field16@61-2-15 = SET:set12@61-2-15
field17@78-2-25 = SET:set13@78-2-25
[set11@48-2-11]
field18@50-2-9 = SEQUENCE:seq14@50-2-9
[seq14@50-2-9]
field19@52-2-3 = OBJECT:countryName
field20@57-2-2 = PRINTABLESTRING:"US"
[set12@61-2-15]
field21@63-2-13 = SEQUENCE:seq15@63-2-13
[seq15@63-2-13]
field22@65-2-3 = OBJECT:organizationName
field23@70-2-6 = PRINTABLESTRING:"Amazon"
[set13@78-2-25]
field24@80-2-23 = SEQUENCE:seq16@80-2-23
[seq16@80-2-23]
field25@82-2-3 = OBJECT:commonName
field26@87-2-16 = PRINTABLESTRING:"Amazon\ Root\ CA\ 3"
[seq7@105-2-30]
field27@107-2-13 = UTCTIME:150526000000Z
field28@122-2-13 = UTCTIME:400526000000Z
[seq8@137-2-57]
field29@139-2-11 = SET:set17@139-2-11
field30@152-2-15 = SET:set18@152-2-15
field31@169-2-25 = SET:set19@169-2-25
[set17@139-2-11]
field32@141-2-9 = SEQUENCE:seq20@141-2-9
[seq20@141-2-9]
field33@143-2-3 = OBJECT:countryName
field34@148-2-2 = PRINTABLESTRING:"US"
[set18@152-2-15]
field35@154-2-13 = SEQUENCE:seq21@154-2-13
[seq21@154-2-13]
field36@156-2-3 = OBJECT:organizationName
field37@161-2-6 = PRINTABLESTRING:"Amazon"
[set19@169-2-25]
field38@171-2-23 = SEQUENCE:seq22@171-2-23
[seq22@171-2-23]
field39@173-2-3 = OBJECT:commonName
field40@178-2-16 = PRINTABLESTRING:"Amazon\ Root\ CA\ 3"
[seq9@196-2-89]
field41@198-2-19 = SEQUENCE:seq23@198-2-19
field42@219-2-66 = FORMAT:HEX,BITSTRING:042997A7C6417FC00D9BE8011B56C6F252A5BA2DB212E8D22ED7FAC9C5D8AA6D1F73813B3B986B397C33A5C54E868E8017686245577D44581DB337E56708EB66DE
[seq23@198-2-19]
field43@200-2-7 = OBJECT:id-ecPublicKey
field44@209-2-8 = OBJECT:prime256v1
[seq10@287-2-66]
field45@289-2-64 = SEQUENCE:seq24@289-2-64
[seq24@289-2-64]
field46@291-2-15 = SEQUENCE:seq25@291-2-15
field47@308-2-14 = SEQUENCE:seq26@308-2-14
field48@324-2-29 = SEQUENCE:seq27@324-2-29
[seq25@291-2-15]
field49@293-2-3 = OBJECT:X509v3 Basic Constraints
field50@298-2-1 = BOOLEAN:true
field51@301-2-5 = FORMAT:HEX,OCTETSTRING:30030101FF
[seq26@308-2-14]
field52@310-2-3 = OBJECT:X509v3 Key Usage
field53@315-2-1 = BOOLEAN:true
field54@318-2-4 = FORMAT:HEX,OCTETSTRING:03020186
[seq27@324-2-29]
field55@326-2-3 = OBJECT:X509v3 Subject Key Identifier
field56@331-2-22 = FORMAT:HEX,OCTETSTRING:0414ABB6DBD7069E37AC3086079170C79CC419B178C0
[seq3@355-2-10]
field57@357-2-8 = OBJECT:ecdsa-with-SHA256
$ echo $?
0
```

A return code of ```0``` indicates success.

This text representation (what we call a template) can be edited at will before
going back to the original format of the certificate. For the sake of this
example, and in order to validate the concept, we will not edit it. We simply
convert this template back to its original form using
```ASN1_generate_nconf(3)```.  This is done in 2 steps, first convert it to a
DER encoded file, then convert this DER file to PEM format:

```
$ openssl asn1parse -genconf Amazon_Root_CA_3.tpl -out Amazon_Root_CA_3_new.der
$ openssl x509 -in Amazon_Root_CA_3_new.der -out Amazon_Root_CA_3_new.pem -outform PEM
```

We can see that the original file and the one we regenerated are identical:
```
$ diff -u /etc/ssl/certs/Amazon_Root_CA_3.pem Amazon_Root_CA_3_new.pem
$ echo $?
0
```

See [this page](EXAMPLES.md) for more examples.

```asn1template.pl``` is similar to https://github.com/google/der-ascii .

It works by reading the output of the ```asn1parse``` OpenSSL app in order to build
an internal structure that is then dumped to the equivalent
```ASN1_generate_nconf(3)``` compatible textual representation.

The syntax of this textual representation is documented in the man page of
```ASN1_generate_nconf(3)```:

```bash
$ man 3 ASN1_generate_nconf
```

This function is reachable via the ```-genconf``` option of the ```asn1parse```
OpenSSL app (more info in the manual page: ```man asn1parse``` or ```man
openssl-asn1parse```).

The tool has been tested against the test certificate corpus available at
https://github.com/johndoe31415/x509-cert-testcorpus (~1.7M certificates).

The tests consist in the conversion from DER to template using
```asn1template.pl```, then back to DER using the ```-genconf``` option of the
```asn1parse``` OpenSSL app. The resulting DER file should be identical to the original one.
From the 1 740 319 available certificates, only 32 do not pass the conversion tests.

The reasons were:
- Illegal characters in PrintableStrings for 30 of them
- Line feed in an OCTET STRING for another one
- Unicode butchery for the last one

(See [limitations](#limitations) section below for more info)


### Dependencies

- perl
- openssl


### Naming Convention

Fields and sequences/sets naming convention is the following:
```
[type][id]@[offset]-[header_length]-[length]
```
where
- [type] is either the string "field", "seq" or "set",
- [id] is a incremental numeric identifier,
- [offset] is the offset of the object or sequence in the original encoded file,
- [header_length] is length of the header preceding the data in the original encoded file,
- [length] is the length of the data in the original encoded file.

For instance,
```
seq2@3-4-567
```
is the second sequence. It is located at the third byte in the original
encoded file. The header preceding the data is encoded using 4 bytes and the
data account for 567 bytes for this sequence.

This can be disabled using '-s' option (or long version '--simple-labels').

### Output & Return Codes

The template is printed on STDOUT, error messages are printed on STDERR, if
any.

Return codes:
- ```0```: Success.
- ```1```: Command line arguments error.
- ```2```: Unparseable line encountered.
- ```3```: Indefinite length encoding detected.

### Multi-root data structures

The ```asn1parse``` OpenSSL app is able to read concatenated DER structures as
if it was a single structure. The result is a dump with multiple objects at
depth 0.

Here is an example of such structure:

```
$ openssl asn1parse -in TS48\ V5.0\ eSIM_GTP_SAIP2.3_BERTLV_SUCI.der -inform D -i
    0:d=0  hl=3 l= 159 cons: cont [ 0 ]
[...]
  162:d=0  hl=4 l= 775 cons: cont [ 16 ]
[...]
  941:d=0  hl=2 l=  40 cons: cont [ 3 ]
[...]
  983:d=0  hl=2 l=  76 cons: cont [ 2 ]
[...]
 1061:d=0  hl=4 l= 531 cons: cont [ 18 ]
[...]
```

The ```-genconf``` option of the ```asn1parse``` OpenSSL app is not able to
generate such multi-root structures. In order to deal with this issue, the
```asn1template.pl``` command, with its ```--multi-root``` option, produces a
template that wraps the concatenated structures into a top level SEQUENCE.
This wrapping sequence can then be stripped using the ```unwrap_multiroot.pl```
command after template edition.

Here is a full example, based on an eSIM test file
(coming from https://github.com/GSMATerminals/Generic-eUICC-Test-Profile-for-Device-Testing-Public/):

```
$ ./asn1template.pl --multi-root TS48\ V5.0\ eSIM_GTP_SAIP2.3_BERTLV_SUCI.der > TS48\ V5.0\ eSIM_GTP_SAIP2.3_BERTLV_SUCI.der.tpl
$ openssl asn1parse -genconf TS48\ V5.0\ eSIM_GTP_SAIP2.3_BERTLV_SUCI.der.tpl -out TS48\ V5.0\ eSIM_GTP_SAIP2.3_BERTLV_SUCI.der.tpl.der
$ ./unwrap_multiroot.pl TS48\ V5.0\ eSIM_GTP_SAIP2.3_BERTLV_SUCI.der.tpl.der
Output written to file "TS48 V5.0 eSIM_GTP_SAIP2.3_BERTLV_SUCI.der.tpl.der.unwrapped".
$ diff TS48\ V5.0\ eSIM_GTP_SAIP2.3_BERTLV_SUCI.der TS48\ V5.0\ eSIM_GTP_SAIP2.3_BERTLV_SUCI.der.tpl.der.unwrapped
$ echo $?
0
```

## Limitations

This script was written many years ago as a quick and dirty PoC. It was then
improved to support DER structures found in the wild (i.e. certificates).

This tool has the same limitations as ```ASN1_generate_nconf(3)```:
 - it does not support indefinite length encoding, regular length encoding is
   used instead. EOC tags are preserved.
 - it might produce a template that is not supported by ASN1_generate_nconf(3),
   this is the case with some CN encoded as PrintableString that contain
   forbidden characters such as ```*```, ```@```, ```&``` or ```_```
   (https://en.wikipedia.org/wiki/PrintableString).

It will not output explicit tags as is, instead it will output a combination of
implicit tags and sequences that will ultimately produce an equivalent output.
Please refer to example #5 in [examples](EXAMPLES.md) section.

Line feeds in OCTET STRINGs break the conversion.

Unicode strings are sometimes broken and might require adjustments.

ENUM and some string types are not supported yet by ```asn1template.pl```.

## License

Copyright (c) 2022-2024 William Robinet <willi@mrobi.net>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
