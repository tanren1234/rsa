> Java 解密 Demo


import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class RSADecrypt {

    /**
     * 签名算法
     * java.security.Signature#signatureInfo
     *
     * signatureInfo.put("sun.security.rsa.RSASignature$MD2withRSA", TRUE);
     * signatureInfo.put("sun.security.rsa.RSASignature$MD5withRSA", TRUE);
     * signatureInfo.put("sun.security.rsa.RSASignature$SHA1withRSA", TRUE);
     * signatureInfo.put("sun.security.rsa.RSASignature$SHA256withRSA", TRUE);
     * signatureInfo.put("sun.security.rsa.RSASignature$SHA384withRSA", TRUE);
     * signatureInfo.put("sun.security.rsa.RSASignature$SHA512withRSA", TRUE);
     */
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static final String KEY_ALGORITHM = "RSA";
    private static final int MAX_DECRYPT_BLOCK = 256;
    /**
     * 私钥解密
     *
     * @param encryptedData 已加密数据
     * @param privateKey    私钥(BASE64编码)
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey) throws Exception {
        byte[] keyBytes = base64Decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateK);
        return segmented(cipher, encryptedData, MAX_DECRYPT_BLOCK);
    }

    /**
     * 公钥解密
     *
     * @param encryptedData 已加密数据
     * @param publicKey     公钥(BASE64编码)
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey) throws Exception {
        byte[] keyBytes = base64Decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        return segmented(cipher, encryptedData, MAX_DECRYPT_BLOCK);
    }

    /**
     * 分段处理加解密避免JDK的
     * Exception in thread "main" javax.crypto.IllegalBlockSizeException: Data must not be longer than 128 bytes
     *
     * @param cipher    加解密的密码对象
     * @param data      加解密的数据
     * @param MAX_BLOCK 最大处理长度
     */
    private static byte[] segmented(Cipher cipher, byte[] data, final int MAX_BLOCK) throws Exception {
        int inputLen = data.length;
        byte[] cache;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0, offSet = 0; inputLen - offSet > 0; i++, offSet = i * MAX_BLOCK) {
            if (inputLen - offSet > MAX_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }


    /**
     * base64转码
     */
    public static String base64ToString(byte[] target) {
        return Base64.getEncoder().encodeToString(target);
    }

    /**
     * base64解码
     */
    public static byte[] base64Decode(String target) {
        return Base64.getDecoder().decode(target);
    }

    public static void main (String[] args) {
   String dataString = new String(decryptByPrivateKey(DataCenterRSA.base64Decode(data), PRIVATE_KEY));

    }

}
