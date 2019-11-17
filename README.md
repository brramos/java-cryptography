## RSA Key Pair
openssl genrsa
> creates a 512 bit long modulus

openssl genrsa 2048
> create a 2048 bit long modulus

openssl genrsa -aes256 2048
> creates a private key with pass phrase

openssl genrsa -aes256 -out billy.key 2048
> creates a private key with pass phrase to file

## Certificate Signing Request
openssl req -new -key billy.key -days 365 -out billy.csr
> creates a certificate signing Request

openssl req -text -in billy.csr
> opens certificate signing request in text format


## Personal information exchange
> CA will provide *.cer from the *.csr

openssl x509 -in billy.cer -text
> opens certificate in text format

openssl pkcs12 -export -in billy.cer -inkey billy.key -out billy.pfx
> combines certificate and key to create the personal information exchange
