package burp;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.xml.bind.DatatypeConverter;

public class SM4 {

    private static final String ALGORITHM_NAME = "SM4";
    private static final String CIPHER_TRANSFORMATION_CBC = "SM4/CBC/PKCS5Padding";
    private static final String CIPHER_TRANSFORMATION_ECB = "SM4/ECB/PKCS5Padding";
    private static final int IV_LENGTH = 16;
    public static void main(String[] args) throws Exception {
        // Use DatatypeConverter.printHexBinary() byte[] Ciphertext To Hex(string)
        // Use DatatypeConverter.parseHexBinary() byte[] Hex(string) To Ciphertext
        String key = "mySecretKey12345";
        String iv = "myInitialization";
        byte[] keyBytes = key.getBytes("UTF-8");  //key = "mySecretKey12345";
//        byte[] keyBytes = DatatypeConverter.parseHexBinary(key);  //key = "c3d881a19239e89bba2984eefbcd7596"
        byte[] ivBytes = iv.getBytes("UTF-8"); // iv = "myInitialization";
//        byte[] keyBytes = DatatypeConverter.parseHexBinary(iv);  //iv = "c3d881a19239e89bba2984eefbcd7596"

        String plaintext = "Hello, puppet!";

        String ciphertextCbc = encryptCBC(plaintext, keyBytes, ivBytes);
        System.out.println("CBC Ciphertext: " + ciphertextCbc);

        String decryptedCbc = decryptCBC(ciphertextCbc, keyBytes, ivBytes);
        System.out.println("CBC Decrypted: " + decryptedCbc);

        String ciphertextEcb = encryptECB(plaintext, keyBytes);
        System.out.println("ECB ciphertext: " + ciphertextEcb);

        String decryptedEcb = decryptECB(ciphertextEcb, keyBytes);
        System.out.println("ECB Decrypted: " + decryptedEcb);
    }

    public static String encryptCBC(String plainText, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM_NAME);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv, 0, IV_LENGTH);
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION_CBC);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));
//        return Base64.encodeBase64String(encrypted);
        return DatatypeConverter.printHexBinary(encrypted);
    }

    public static String decryptCBC(String encryptedText, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM_NAME);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv, 0, IV_LENGTH);
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION_CBC);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
//        byte[] decrypted = cipher.doFinal(Base64.decodeBase64(encryptedText));
        byte[] decrypted = cipher.doFinal(DatatypeConverter.parseHexBinary(encryptedText));
        return new String(decrypted, "UTF-8");
    }

    public static String encryptECB(String plainText, byte[] key) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM_NAME);
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION_ECB);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));
//        return Base64.encodeBase64String(encrypted);
        return DatatypeConverter.printHexBinary(encrypted);
    }

    public static String decryptECB(String encryptedText, byte[] key) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM_NAME);
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION_ECB);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
//        byte[] decrypted = cipher.doFinal(Base64.decodeBase64(encryptedText));
        byte[] decrypted = cipher.doFinal(DatatypeConverter.parseHexBinary(encryptedText));
        //解决编码问题
        return new String(decrypted, "GBK");
//        return new String(decrypted, "UTF-8");
    }
}
