import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/*
 * Skeleton code for class SessionKey
 */

class SessionKey {

    private SecretKey secretKey;
    /*
     * Constructor to create a secret key of a given length
     */
    // TODO: 2022-11-16   creates a random SessionKey of the specified length (in bits)
    public SessionKey(Integer length) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(length);
        secretKey = keyGen.generateKey();
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    // TODO: 2022-11-16  creates a SessionKey from a byte array.
    public SessionKey(byte[] keybytes) throws NoSuchAlgorithmException {
//        int len = keybytes.length * 8;
//        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
//        keyGen.init(len); // for example
//        secretKey = keyGen.generateKey();
        secretKey = new SecretKeySpec(keybytes, 0, keybytes.length, "AES");
    }

    /*
     * Return the secret key
     */
    // TODO: 2022-11-16 retrieve the SecretKey from a SessionKey object
    public SecretKey getSecretKey() {
        return secretKey;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    // TODO: 2022-11-16 export a key as a sequence of bytes.
    public byte[] getKeyBytes() {
        byte[] bkey = secretKey.getEncoded();
        return bkey;
    }
}
