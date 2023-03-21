# ASN1 templating for fun and profit

## Description

This tool takes a DER or PEM encoded ASN1 structure and outputs the equivalent
textual description that can be edited and later be fed to
ASN1_generate_nconf(3) in order to build the equivalent DER encoded ASN1
structure.

See [examples](EXAMPLES.md).

It's similar to https://github.com/google/der-ascii .

It works by reading the output of the asn1parse OpenSSL app in order to build
an internal structure that is then dumped to the equivalent
ASN1_generate_nconf(3) compatible textual representation.

The syntax of this textual representation is documented in the man page of
ASN1_generate_nconf(3):

```bash
$ man 3 ASN1_generate_nconf
```

This function is reachable via the ```-genconf``` option of the asn1parse
OpenSSL app (more info in the manual page: ```man asn1parse``` or ```man
openssl-asn1parse```).

The tool has been tested against the test certificate corpus available at
https://github.com/johndoe31415/x509-cert-testcorpus (~1.7M certificates).


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


## Limitations

This script was written many years ago as a quick and dirty PoC. It was then
improved to support DER structures found in the wild (i.e. certificates).

This tool has the same limitations as ASN1_generate_nconf(3):
 - it does not support indefinite length encoding
 - it might produce a template that is not supported by ASN1_generate_nconf(3),
   this is the case with some CN encoded as PrintableString that contain
   forbidden characters such as ```*```, ```@```, ```&``` or ```_```
   (https://en.wikipedia.org/wiki/PrintableString).

It will not output explicit tags as is, instead it will output a combination of
implicit tags and sequences that will ultimately produce an equivalent output.
Please refer to example #5 in [examples](EXAMPLES.md) section.
