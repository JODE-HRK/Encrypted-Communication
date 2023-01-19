import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class HandshakeCrypto {

	private PublicKey publicKey;
	private PrivateKey privateKey;
	private boolean isPrivate = false;

	public static final String P1_BEGIN_MARKER
			= "-----BEGIN RSA PRIVATE KEY"; //$NON-NLS-1$
	public static final String P1_END_MARKER
			= "-----END RSA PRIVATE KEY"; //$NON-NLS-1$

	// Private key file using PKCS #8 encoding
	public static final String P8_BEGIN_MARKER
			= "-----BEGIN PRIVATE KEY"; //$NON-NLS-1$
	public static final String P8_END_MARKER
			= "-----END PRIVATE KEY"; //$NON-NLS-1$
	/*
	 * Constructor to create an instance for encryption/decryption with a public key.
	 * The public key is given as a X509 certificate.
	 */
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
		isPrivate = false;
		publicKey = handshakeCertificate.getCertificate().getPublicKey();
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */

	public HandshakeCrypto(byte[] keybytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
		isPrivate = true;
		String privateKeyPEM = Base64.getEncoder().encodeToString(keybytes);
		privateKeyPEM = privateKeyPEM.replace(P1_BEGIN_MARKER, "");
		privateKeyPEM = privateKeyPEM.replace( P1_END_MARKER,"");
		privateKeyPEM = privateKeyPEM.replace(P8_BEGIN_MARKER, "");
		privateKeyPEM = privateKeyPEM.replace(P8_END_MARKER,"");
		byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
		KeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		privateKey = factory.generatePrivate(keySpec);
	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
    public byte[] decrypt(byte[] ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		if (isPrivate)
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
		else
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
		byte[] decryptedMessage = cipher.doFinal(ciphertext);
		return decryptedMessage;
    }

	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
    public byte [] encrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		if (isPrivate)
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		else
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] bytes = cipher.doFinal(plaintext);
		return bytes;
    }
}
