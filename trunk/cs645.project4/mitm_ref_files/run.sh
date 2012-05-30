java -cp $CLASSPATH:.:iaik_jce.jar mitm/MITMProxyServer -localHost localhost -localPort 8888 -outputFile output.txt -keyStore FakeCAStore -keyStorePassword passphrase
