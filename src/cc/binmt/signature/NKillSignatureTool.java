package cc.binmt.signature;

import java.io.*;
import java.security.cert.Certificate;
import java.util.*;
import bin.zip.ZipEntry;
import bin.zip.ZipFile;
//import bin.zip.ZipOutputStream;
import bin.util.StreamUtil;

import sun.security.pkcs.PKCS7;

public class NKillSignatureTool {

    public static void main(String[] args) throws Exception {
        byte[] signatures;
        String apkPath;
        if (args.length == 1) {
            apkPath = args[0];
        } else {
            System.out.printf("usage: java -jar getSignature.jar base.apk");
            return;
        }
        if (apkPath == null || !new File(apkPath).isFile()) {
            System.out.printf("E: base.apk don't exist!");
            return;
        }
        signatures = getApkSignatureData(new File(apkPath));
        if (signatures == null) {
            throw new NullPointerException("E: Signatures is null");
        } else {
            System.out.printf("apk signature: " + Base64.getEncoder().encodeToString(signatures));
        }
    }

    private static byte[] getApkSignatureData(File apkFile) throws Exception {
        ZipFile zipFile = new ZipFile(apkFile);
        Enumeration<ZipEntry> entries = zipFile.getEntries();
        while (entries.hasMoreElements()) {
            ZipEntry ze = entries.nextElement();
            String name = ze.getName().toUpperCase();
            if (name.startsWith("META-INF/") && (name.endsWith(".RSA") || name.endsWith(".DSA"))) {
                PKCS7 pkcs7 = new PKCS7(StreamUtil.readBytes(zipFile.getInputStream(ze)));
                Certificate[] certs = pkcs7.getCertificates();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                DataOutputStream dos = new DataOutputStream(baos);
                dos.write(certs.length);
                for (int i = 0; i < certs.length; i++) {
                    byte[] data = certs[i].getEncoded();
                    //System.out.printf("I: SignatureHash[%d] -> %08x\n", i, Arrays.hashCode(data));
                    dos.writeInt(data.length);
                    dos.write(data);
                }
                return baos.toByteArray();
            }
        }
        throw new Exception("E: META-INF/XXX.RSA (DSA) file not found!");
    }

}
