# getSignature
- 获取base64编码后的应用签名数据

- 使用方法
获取base64编码后的应用签名数据：
```shell
java -jar getSignature.jar base.apk
```

修改AndroidManifest.xml的application入口
```shell
java -jar getSignature.jar AndroidManifest.xml "com.example.applicatiom"
```

- 核心代码来自[ApkSignatureKiller](https://github.com/L-JINBIN/ApkSignatureKiller)
