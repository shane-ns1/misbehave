#! /bin/bash

#Country Name (2 letter code) [XX]:
#State or Province Name (full name) []:
#Locality Name (eg, city) [Default City]:
#Organization Name (eg, company) [Default Company Ltd]:
#Organizational Unit Name (eg, section) []:
#Common Name (eg, your name or your server's hostname) []:
#Email Address []:

openssl req -new \
    -x509 -days 28 -nodes \
    -out stunnel-public.pem \
    -keyout stunnel-private.pem \
    -subj "/C=XX"
