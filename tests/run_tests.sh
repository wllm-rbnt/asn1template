#!/bin/bash

set -e

cd tests
mkdir -p certs crls smime esim

echo "Testing certificates ..."
cd certs
rm -f ./*tpl* ./*der

remote_hosts="\
kernel.org \
apple.com \
microsoft.com \
office365.microsoft.com \
google.com \
gmail.com \
youtube.com \
github.com \
amazon.com \
facebook.com \
twitter.com \
x.com \
yandex.ru \
akamai.com \
cloudflare.com \
ebay.co.jp \
mynic.my \
www.luxtrust.lu \
"

for i in $remote_hosts; do
    echo "${i}"
    echo | openssl s_client -connect "${i}:443" 2>/dev/null | openssl x509 -out "${i}.der" -outform D
    ../../asn1template.pl "${i}.der" > "${i}.tpl"
    openssl asn1parse -genconf "${i}.tpl" -out "${i}.tpl.der" > /dev/null 2>&1
    diff "${i}.der" "${i}.tpl.der" > /dev/null 2>&1
    echo $?
done

echo "Testing CRLs ..."
cd ../crls
rm -f ./*tpl* ./*crl
wget http://geant.crl.sectigo.com/GEANTOVRSACA4.crl -o /dev/null -O GEANTOVRSACA4.crl
wget http://crls.pki.goog/gts1c3/fVJxbV-Ktmk.crl -o /dev/null -O fVJxbV-Ktmk.crl

for i in ./*crl; do
    echo "${i}"
    ../../asn1template.pl "${i}" > "${i}.tpl"
    openssl asn1parse -genconf "${i}.tpl" -out "${i}.tpl.der" > /dev/null 2>&1
    diff "${i}" "${i}.tpl.der" > /dev/null 2>&1
    echo $?
done

echo "Testing PKCS7 structures ..."
cd ../smime
rm -f ./*tpl* ./*p7s
wget https://www.mail-archive.com/atom-protocol@mail.imc.org/msg02042/smime.p7s -O msg02042_smime.p7s
wget https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg03294/smime.p7s -O msg03294_smime.p7s
for i in ./*p7s; do
    echo "${i}"
    ../../asn1template.pl "${i}" > "${i}.tpl" || true
    openssl asn1parse -genconf "${i}.tpl" -out "${i}.tpl.der" > /dev/null 2>&1
    diff "${i}" "${i}.tpl.der" > /dev/null 2>&1 || true
    echo $?
done

echo "Testing eSIM structures ..."
cd ../esim
rm -f ./*tpl* ./*der ./*unwrapped
wget https://github.com/GSMATerminals/Generic-eUICC-Test-Profile-for-Device-Testing-Public/raw/master/GSMA_TS48_eSIM_GTP_Profile_Package_v5.zip
unzip GSMA_TS48_eSIM_GTP_Profile_Package_v5.zip \*der
while read -r i; do
    echo "${i}"
    ../../asn1template.pl -m "${i}" > "${i}.tpl"
    openssl asn1parse -genconf "${i}.tpl" -out "${i}.tpl.der" > /dev/null 2>&1
    ../../unwrap_multiroot.pl "${i}.tpl.der"
    diff "${i}" "${i}.tpl.der.unwrapped" > /dev/null 2>&1
    echo $?
done < <(ls -1 ./*der)

