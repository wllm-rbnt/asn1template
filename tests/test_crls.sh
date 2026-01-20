#!/bin/bash

cd tests
mkdir -p crls

echo "### Testing CRLs ..."
cd ./crls
rm -f ./*tpl* ./*crl
wget http://geant.crl.sectigo.com/GEANTOVRSACA4.crl -O GEANTOVRSACA4.crl
wget http://crls.pki.goog/gts1c3/fVJxbV-Ktmk.crl -O fVJxbV-Ktmk.crl

for i in ./*crl; do
    echo -n "${i} ... "
    ../../asn1template.pl "${i}" > "${i}.tpl"
    openssl asn1parse -genconf "${i}.tpl" -out "${i}.tpl.der" > /dev/null 2>&1
    diff "${i}" "${i}.tpl.der" > /dev/null 2>&1 && echo "ok" || echo "not ok"
done
