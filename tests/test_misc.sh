#!/bin/bash

cd tests
mkdir -p misc

echo "### Testing synthetic structures"
cd misc
rm -f ./*tpl* ./*der

echo -n "Testing embedded SEQs and SETs ... "
cat > setsandseqs.tpl << EOF
asn1 = SEQ:seq1
[seq1]
field1 = SEQ:seq2
[seq2]
field2 = SEQ:seq3
field3 = SET:set4
[seq3]
field4 = INT:1
[set4]
field5 = SEQ:seq5
[seq5]
field6 = SEQ:seq6
[seq6]
field7 = INT:0
EOF

openssl asn1parse -genconf setsandseqs.tpl -out setsandseqs.der > /dev/null 2>&1
../../asn1template.pl setsandseqs.der > setsandseqs.der.tpl
openssl asn1parse -genconf setsandseqs.der.tpl -out setsandseqs.der.tpl.der > /dev/null 2>&1
diff setsandseqs.der setsandseqs.der.tpl.der > /dev/null 2>&1 && echo "ok" || echo "not ok"
