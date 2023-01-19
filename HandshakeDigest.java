import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HandshakeDigest {

    private MessageDigest messageDigest;
    private byte[] digest;

    /*
     * Constructor -- initialise a digest for SHA-256
     */

    public HandshakeDigest() throws NoSuchAlgorithmException {
        // Static getInstance method is called with hashing SHA
        this.messageDigest = MessageDigest.getInstance("SHA-256");
    }

    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
        this.messageDigest.update(input);
    }

    /*
     * Compute final digest
     */
    public byte[] digest() {
//        return Base64.getEncoder().encodeToString(finalDigest).getBytes();
        this.digest = this.messageDigest.digest();
        return this.digest;
    }
};
