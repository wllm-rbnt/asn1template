#!/bin/bash

set -e

cd tests
mkdir -p esim

echo "Testing eSIM structures ..."
cd ./esim
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
