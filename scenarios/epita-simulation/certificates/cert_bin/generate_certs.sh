#! /bin/bash

for index in {11..1000}
do
    ./certify generate-key ticket${index}.key
    ./certify generate-ticket --sign-key aa.key --sign-cert aa.cert --subject-key ticket${index}.key ticket${index}.cert
done