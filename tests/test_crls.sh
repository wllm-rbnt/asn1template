#!/bin/bash

cd tests
mkdir -p crls

echo "### Testing CRLs ..."
cd ./crls
rm -f ./*tpl* ./*crl
wget http://geant.crl.sectigo.com/GEANTOVRSACA4.crl -O GEANTOVRSACA4.crl
wget http://c.pki.goog/we2/dTM3-0hpWfE.crl -O dTM3-0hpWfE.crl

for i in ./*crl; do
    echo -n "${i} ... "
    ../../asn1template.pl "${i}" > "${i}.tpl"
    openssl asn1parse -genconf "${i}.tpl" -out "${i}.tpl.der" > /dev/null 2>&1
    diff "${i}" "${i}.tpl.der" > /dev/null 2>&1 && echo "ok" || echo "not ok"
done
