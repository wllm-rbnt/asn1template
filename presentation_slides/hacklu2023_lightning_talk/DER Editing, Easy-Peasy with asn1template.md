%title: asn1template: Your DER Editing BFF
%author: William Robinet - @wr@infosec.exchange - Conostix S.A. - https://github.com/wllm-rbnt/asn1template
%date: 2023-10-19

-> DER Editing, Easy-Peasy with asn1template <-
=========
-> William Robinet <-
-> Hack.lu - 2023-10-19 <-

-------------------------------------------------
-> `DER` is binary TLV encoding for `ASN.1` <-

   00000000  30 82 04 ef 30 82 03 d7  a0 03 02 01 02 02 12 03  |0...0...........|
   00000010  0b 03 30 e1 3c aa df b5  51 f5 60 4a 77 6f 51 5f  |..0.<...Q.`JwoQ_|
   00000020  b6 30 0d 06 09 2a 86 48  86 f7 0d 01 01 0b 05 00  |.0...*.H........|
   00000030  30 32 31 0b 30 09 06 03  55 04 06 13 02 55 53 31  |021.0...U....US1|
   00000040  16 30 14 06 03 55 04 0a  13 0d 4c 65 74 27 73 20  |.0...U....Let's |
   00000050  45 6e 63 72 79 70 74 31  0b 30 09 06 03 55 04 03  |Encrypt1.0...U..|
   00000060  13 02 52 33 30 1e 17 0d  32 33 31 30 31 36 30 31  |..R30...23101601|
   00000070  31 34 34 30 5a 17 0d 32  34 30 31 31 34 30 31 31  |1440Z..240114011|
   00000080  34 33 39 5a 30 17 31 15  30 13 06 03 55 04 03 13  |439Z0.1.0...U...|
   00000090  0c 32 30 32 33 2e 68 61  63 6b 2e 6c 75 30 82 01  |.2023.hack.lu0..|
   000000a0  22 30 0d 06 09 2a 86 48  86 f7 0d 01 01 01 05 00  |"0...*.H........|
   000000b0  03 82 01 0f 00 30 82 01  0a 02 82 01 01 00 d8 ae  |.....0..........|
   000000c0  55 47 20 b4 6f 96 f9 b2  34 2b 71 3d f5 dc 34 32  |UG .o...4+q=..42|
   000000d0  9a ad 25 84 35 78 40 5a  b4 80 a1 1e fd e8 5a 43  |..%.5x@Z......ZC|
   000000e0  30 af 84 7f 3b c2 c6 a7  29 dd 99 e6 b7 e6 46 93  |0...;...).....F.|
   000000f0  59 02 f9 81 05 60 90 70  00 af 66 70 fc 73 d5 cd  |Y....`.p..fp.s..|
   00000100  d4 af dc 97 95 4f 07 d7  28 bf 64 e0 39 f5 b0 c4  |.....O..(.d.9...|
   00000110  5b 46 6b b2 db bd 80 6c  96 51 ba 06 05 13 7f 78  |[Fk....l.Q.....x|
   00000120  58 96 b9 35 b3 b6 4b a2  bc ab 29 22 e6 d8 41 cc  |X..5..K...)"..A.|
   [...]


-------------------------------------------------
-> `openssl asn1parse` output format <-

   8:d=2  hl=2 l=   3 cons:   cont [ 0 ]        
   10:d=3  hl=2 l=   1 prim:    INTEGER           :02
   13:d=2  hl=2 l=  18 prim:   INTEGER           :030B0330E13CAADFB55[...]
   33:d=2  hl=2 l=  13 cons:   SEQUENCE          
   35:d=3  hl=2 l=   9 prim:    OBJECT            :sha256WithRSAEncryption
   46:d=3  hl=2 l=   0 prim:    NULL              
   48:d=2  hl=2 l=  50 cons:   SEQUENCE          
   50:d=3  hl=2 l=  11 cons:    SET               
   52:d=4  hl=2 l=   9 cons:     SEQUENCE          
   54:d=5  hl=2 l=   3 prim:      OBJECT            :countryName
   59:d=5  hl=2 l=   2 prim:      PRINTABLESTRING   :US
   63:d=3  hl=2 l=  22 cons:    SET               
   65:d=4  hl=2 l=  20 cons:     SEQUENCE          
   67:d=5  hl=2 l=   3 prim:      OBJECT            :organizationName
   72:d=5  hl=2 l=  13 prim:      PRINTABLESTRING   :Let's Encrypt
   87:d=3  hl=2 l=  11 cons:    SET               
   89:d=4  hl=2 l=   9 cons:     SEQUENCE          
   91:d=5  hl=2 l=   3 prim:      OBJECT            :commonName
   96:d=5  hl=2 l=   2 prim:      PRINTABLESTRING   :R3
   [...]


-------------------------------------------------
-> `ASN1_generate_nconf(3)` input format <-

   asn1 = SEQUENCE:seq1@0-4-1263
   [seq1@0-4-1263]
   field2@4-4-983 = SEQUENCE:seq2@4-4-983
   field3@991-2-13 = SEQUENCE:seq3@991-2-13
   field4@1006-4-257 = FORMAT:HEX,BITSTRING:30C8DC02437D9C77C528ABEDAB90D491[...]
   [seq2@4-4-983]
   field5@8-2-3 = IMPLICIT:0C,SEQUENCE:seq4@8-2-3
   field6@13-2-18 = INTEGER:0x030B0330E13CAADFB551F5604A776F515FB6
   field7@33-2-13 = SEQUENCE:seq5@33-2-13
   field8@48-2-50 = SEQUENCE:seq6@48-2-50
   field9@100-2-30 = SEQUENCE:seq7@100-2-30
   field10@132-2-23 = SEQUENCE:seq8@132-2-23
   field11@157-4-290 = SEQUENCE:seq9@157-4-290
   field12@451-4-536 = IMPLICIT:3C,SEQUENCE:seq10@451-4-536
   [seq4@8-2-3]
   field13@10-2-1 = INTEGER:0x02
   [seq5@33-2-13]
   field14@35-2-9 = OBJECT:sha256WithRSAEncryption
   field15@46-2-0 = NULL
   [...]


-------------------------------------------------

-> # asn1template <-

-> `DER == ASN1_generate_nconf(asn1template(asn1parse(DER)))` <-

- `openssl asn1parse` dumps the DER structure as text
- [asn1template](https://github.com/wllm-rbnt/asn1template) converts this textual description to OpenSSL configuration syntax
- `ASN1_generate_nconf(3)` generates a new DER structure (reachable through `-genconf` in `asn1parse`)

- Infinite loop in BN_mod_sqrt() reachable when parsing certificates (CVE-2022-0778)
- Possible DoS translating ASN.1 object identifiers (CVE-2023-2650)

- Supports multi-root files (eSIM)


-------------------------------------------------
-> # Demo <-

- Retrieve 2023.hack.lu TLS certificate in `cert.der`:

    echo | openssl s_client -connect 2023.hack.lu:443 | openssl x509 -out cert.der -outform D

- Convert TLS certificate to a template:

    asn1template.pl cert.der > cert.tpl

- Edit cert.tpl (optional)
- Generate (modified) certificate from template:

    openssl asn1parse -genconf cert.tpl -i -out cert.tpl.der

- Visually compare original certificate against modified one:

    meld <(openssl asn1parse -in cert.der -i -inform D) <(openssl asn1parse -in cert.tpl.der -inform D -i)

