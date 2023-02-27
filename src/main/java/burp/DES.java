package burp;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class DES {
    private static final String ALGORITHM = "DES";
    private static final String TRANSFORMATION_CBC = "DES/CBC/PKCS5Padding";
    private static final String TRANSFORMATION_ECB = "DES/ECB/PKCS5Padding";
    public static void main(String[] args) throws Exception {
        String key = "01234567"; // 8 bytes key
        String iv = "12345678"; // 8 bytes IV

        String plaintext = "Hello, puppet!";

        String ciphertextCbc = encryptCBC(plaintext, key, iv);
        System.out.println("CBC Ciphertext: " + ciphertextCbc);

        String decryptedCbc = decryptCBC(ciphertextCbc, key, iv);
        System.out.println("CBC Decrypted: " + decryptedCbc);

        String ciphertextEcb = encryptECB(plaintext, key);
        System.out.println("ECB ciphertext: " + ciphertextEcb);

        String decryptedEcb = decryptECB(ciphertextEcb, key);
        System.out.println("ECB Decrypted: " + decryptedEcb);
    }


    public static String encryptCBC(String plaintext, String key, String iv) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_CBC);
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
            IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
        throw new RuntimeException("Encryption failed", e);
        }
    }

    public static String decryptCBC(String ciphertext, String key, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_CBC);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static String encryptECB(String plaintext, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_ECB);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decryptECB(String ciphertext, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_ECB);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}

