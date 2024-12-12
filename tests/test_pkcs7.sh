#!/bin/bash

set -e

cd tests
mkdir -p smime

echo "### Testing PKCS7 S/MIME structures ..."
cd ./smime
rm -f ./*tpl* ./*p7s
wget https://www.mail-archive.com/atom-protocol@mail.imc.org/msg02042/smime.p7s -O msg02042_smime.p7s
wget https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg03294/smime.p7s -O msg03294_smime.p7s
for i in ./*p7s; do
    echo "${i} ... "
    ! ../../asn1template.pl "${i}" > "${i}.tpl"
    openssl asn1parse -genconf "${i}.tpl" -out "${i}.tpl.der" > /dev/null 2>&1
    ! diff "${i}" "${i}.tpl.der" > /dev/null 2>&1 && echo "ok" || echo "not ok"
done
