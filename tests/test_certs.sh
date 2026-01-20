#!/bin/bash

cd tests
mkdir -p certs

echo "### Testing server certificates"
cd certs
rm -f ./*tpl* ./*der

remote_hosts="\
kernel.org \
apple.com \
microsoft.com \
office365.microsoft.com \
bing.com \
duckduckgo.com \
google.com \
gmail.com \
youtube.com \
github.com \
amazon.com \
facebook.com \
twitter.com \
x.com \
bsky.app \
yandex.ru \
akamai.com \
cloudflare.com \
ebay.co.jp \
mynic.my \
www.luxtrust.lu \
open.spotify.com \
xn--fiq228c.tw \
"

for i in $remote_hosts; do
    echo -n "${i} ... "
    echo | openssl s_client -connect "${i}:443" 2>/dev/null | openssl x509 -out "${i}.der" -outform D
    ../../asn1template.pl "${i}.der" > "${i}.tpl"
    openssl asn1parse -genconf "${i}.tpl" -out "${i}.tpl.der" > /dev/null 2>&1
    diff "${i}.der" "${i}.tpl.der" > /dev/null 2>&1 && echo "ok" || echo "not ok"
done
