# getSignature
- 获取base64编码后的应用签名数据

- 使用方法
```shell
java -jar --add-exports java.base/sun.security.pkcs=ALL-UNNAMED --add-exports java.base/sun.security.x509=ALL-UNNAMED getSignature.jar base.apk
```

- 核心代码来自[ApkSignatureKiller](https://github.com/L-JINBIN/ApkSignatureKiller)
