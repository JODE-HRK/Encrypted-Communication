import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class SessionCipher {

    private byte[] IVBytes;
    private SessionKey sessionKey;
    private Cipher cipher;

    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) throws NoSuchAlgorithmException, NoSuchPaddingException {
        sessionKey = key;

        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] iv = new byte[cipher.getBlockSize()];
        random.nextBytes(iv);
        IVBytes = iv;
    }

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes) throws NoSuchPaddingException, NoSuchAlgorithmException {
        sessionKey = key;

        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IVBytes = ivbytes;
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return sessionKey;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return IVBytes;
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey key = sessionKey.getSecretKey();
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IVBytes));
        CipherOutputStream cipherOutputStream = new CipherOutputStream(os, cipher);
        return cipherOutputStream;
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream) throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey key = sessionKey.getSecretKey();
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IVBytes));
        CipherInputStream cipherInputStream = new CipherInputStream(inputstream, cipher);
        return cipherInputStream;
    }
}
