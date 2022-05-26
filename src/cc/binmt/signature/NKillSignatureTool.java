package cc.binmt.signature;

import java.io.*;
import java.security.cert.Certificate;
import java.util.*;
import bin.zip.ZipEntry;
import bin.zip.ZipFile;
import bin.xml.decode.AXmlDecoder;
import bin.xml.decode.AXmlResourceParser;
import bin.xml.decode.XmlPullParser;
import bin.zip.ZipOutputStream;
import bin.util.StreamUtil;

import sunx.security.pkcs.PKCS7;

public class NKillSignatureTool {
    private static String packageName;
    private static String customApplicationName;
    private static boolean customApplication = false;

    public static void main(String[] args) throws Exception {
        byte[] signatures;
        String apkPath;
        String pmsClass = null;
        if (args.length == 1) {
            apkPath = args[0];
        } else if (args.length == 2) {
            apkPath = args[0];
            pmsClass = args[1];
        } else {
            System.out.printf("usage: java -jar getSignature.jar base.apk\n       java -jar getSignature.jar AndroidManifest.xml \"cc.binmt.signature.PmsHookApplication\"");
            return;
        }
        if (apkPath == null || !new File(apkPath).isFile()) {
            System.out.printf("E: base.apk/AndroidManifest.xml don't exist!");
            return;
        }
        if (apkPath.endsWith(".apk")) {
            signatures = getApkSignatureData(new File(apkPath));
            if (signatures == null) {
                throw new NullPointerException("E: Signatures is null");
            } else {
                System.out.printf("apk signature:" + Base64.getEncoder().encodeToString(signatures));
            }
        } else if (apkPath.endsWith("AndroidManifest.xml")) {
            parseManifest(new File(apkPath), pmsClass);
            if (customApplication) {
                if (customApplicationName.startsWith(".")) {
                    if (packageName == null)
                        throw new NullPointerException("E: Package name is null.");
                    customApplicationName = packageName + customApplicationName;
                }
                System.out.printf("apk application:" + customApplicationName);
            }
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

    private static void parseManifest(File axmlFile, String pmsClass) throws IOException {
        InputStream is = new FileInputStream(axmlFile);
        AXmlDecoder axml = AXmlDecoder.decode(is);
        AXmlResourceParser parser = new AXmlResourceParser();
        parser.open(new ByteArrayInputStream(axml.getData()), axml.mTableStrings);
        boolean success = false;

        int type;
        while ((type = parser.next()) != XmlPullParser.END_DOCUMENT) {
            if (type != XmlPullParser.START_TAG)
                continue;
            if (parser.getName().equals("manifest")) {
                int size = parser.getAttributeCount();
                for (int i = 0; i < size; ++i) {
                    if (parser.getAttributeName(i).equals("package")) {
                        packageName = parser.getAttributeValue(i);
                    }
                }
            } else if (parser.getName().equals("application")) {
                int size = parser.getAttributeCount();
                for (int i = 0; i < size; ++i) {
                    if (parser.getAttributeNameResource(i) == 0x01010003) {
                        customApplication = true;
                        customApplicationName = parser.getAttributeValue(i);
                        int index = axml.mTableStrings.getSize();
                        byte[] data = axml.getData();
                        int off = parser.currentAttributeStart + 20 * i;
                        off += 8;
                        writeInt(data, off, index);
                        off += 8;
                        writeInt(data, off, index);
                    }
                }
                if (!customApplication) {
                    int off = parser.currentAttributeStart;
                    byte[] data = axml.getData();
                    byte[] newData = new byte[data.length + 20];
                    System.arraycopy(data, 0, newData, 0, off);
                    System.arraycopy(data, off, newData, off + 20, data.length - off);

                    // chunkSize
                    int chunkSize = readInt(newData, off - 32);
                    writeInt(newData, off - 32, chunkSize + 20);
                    // attributeCount
                    writeInt(newData, off - 8, size + 1);

                    int idIndex = parser.findResourceID(0x01010003);
                    if (idIndex == -1)
                        throw new IOException("idIndex == -1");

                    boolean isMax = true;
                    for (int i = 0; i < size; ++i) {
                        int id = parser.getAttributeNameResource(i);
                        if (id > 0x01010003) {
                            isMax = false;
                            if (i != 0) {
                                System.arraycopy(newData, off + 20, newData, off, 20 * i);
                                off += 20 * i;
                            }
                            break;
                        }
                    }
                    if (isMax) {
                        System.arraycopy(newData, off + 20, newData, off, 20 * size);
                        off += 20 * size;
                    }

                    writeInt(newData, off, axml.mTableStrings.find("http://schemas.android.com/apk/res/android"));
                    writeInt(newData, off + 4, idIndex);
                    writeInt(newData, off + 8, axml.mTableStrings.getSize());
                    writeInt(newData, off + 12, 0x03000008);
                    writeInt(newData, off + 16, axml.mTableStrings.getSize());
                    axml.setData(newData);
                }
                success = true;
                break;
            }
        }
        if (!success)
            throw new IOException();
        ArrayList<String> list = new ArrayList<>(axml.mTableStrings.getSize());
        axml.mTableStrings.getStrings(list);
        //由于某些开发者会检测PmsHookApplication类，故添加一个自定义接口
        if (pmsClass != null) {
            list.add(pmsClass);
        } else {
            list.add("cc.binmt.signature.PmsHookApplication");
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        axml.write(list, baos);
        writeBytesToFile(baos.toByteArray(), axmlFile);
    }

    public static void writeBytesToFile(byte[] bs, File filePath) throws IOException{
        OutputStream out = new FileOutputStream(filePath);
        InputStream is = new ByteArrayInputStream(bs);
        byte[] buff = new byte[1024];
        int len = 0;
        while((len=is.read(buff))!=-1){
            out.write(buff, 0, len);
        }
        is.close();
        out.close();
    }


    private static void writeInt(byte[] data, int off, int value) {
        data[off++] = (byte) (value & 0xFF);
        data[off++] = (byte) ((value >>> 8) & 0xFF);
        data[off++] = (byte) ((value >>> 16) & 0xFF);
        data[off] = (byte) ((value >>> 24) & 0xFF);
    }

    private static int readInt(byte[] data, int off) {
        return data[off + 3] << 24 | (data[off + 2] & 0xFF) << 16 | (data[off + 1] & 0xFF) << 8
                | data[off] & 0xFF;
    }

}
