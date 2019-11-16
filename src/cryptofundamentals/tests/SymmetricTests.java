package cryptofundamentals.tests;

import org.junit.Test;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;

public class SymmetricTests {
    @Test
    public void generateARandomAesKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey key = keyGenerator.generateKey();

        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length);
    }

    @Test
    public void encryptAMessageWithAes() throws Exception {
        String message = "Alice knows Bob's secret.";

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey key = keyGenerator.generateKey();

        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[16];
        random.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        byte[] ciphertext = encryptWithAes(message, key, iv);
        String actualMessage = decryptWithAes(ciphertext, key, iv);

        assertEquals(message, actualMessage);
    }

    private byte[] encryptWithAes(String message, SecretKey key, IvParameterSpec iv) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes.init(Cipher.ENCRYPT_MODE, key, iv);
        CipherOutputStream cipherOut = new CipherOutputStream(out, aes);
        OutputStreamWriter writer = new OutputStreamWriter(cipherOut);

        try {
            writer.write(message);
        }
        finally {
            writer.close();
        }
        return out.toByteArray();
    }

    private String decryptWithAes(byte[] ciphertext, SecretKey key, IvParameterSpec iv) throws Exception {
        ByteArrayInputStream in = new ByteArrayInputStream(ciphertext);
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes.init(Cipher.DECRYPT_MODE, key, iv);
        CipherInputStream cipherIn = new CipherInputStream(in, aes);
        InputStreamReader reader = new InputStreamReader(cipherIn);
        BufferedReader bufferedReader = new BufferedReader(reader);

        try {
            return bufferedReader.readLine();
        }
        finally {
            bufferedReader.close();
        }
    }
}
