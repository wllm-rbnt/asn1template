#!/bin/bash

set -e

./tests/test_certs.sh
./tests/test_crls.sh
./tests/test_esim.sh
./tests/test_pkcs7.sh
