
echo PITJA RETURN

openssl s_client -connect des-tsafirma.redsara.es:8443 -showcerts  2> null2.txt  | openssl x509 -outform PEM > mycertfile.pem

openssl x509 -outform der -in mycertfile.pem -out certificate.der

echo SET PASSWORD  123456789

keytool -import -alias 1 -keystore truststore.jks  -file certificate.der

// Contrasenya 123456789
// Alias 1