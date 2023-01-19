import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.security.*;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;


/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {


    private CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    private X509Certificate x509Certificate;
    private String commonName;
    private String email;
    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    HandshakeCertificate(InputStream instream) throws CertificateException {
        x509Certificate = (X509Certificate) certificateFactory.generateCertificate(instream);
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException {
        InputStream inStream = new ByteArrayInputStream(certbytes);
        x509Certificate = (X509Certificate) certificateFactory.generateCertificate(inStream);
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() throws CertificateEncodingException {
        return x509Certificate.getEncoded();
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return x509Certificate;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        x509Certificate.verify(cacert.getCertificate().getPublicKey());
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        X500Principal principal = x509Certificate.getSubjectX500Principal();
        try {
            LdapName ldapName = new LdapName(principal.getName());
            for (Rdn rdn : ldapName.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("cn")) {
                    return rdn.getValue().toString();
                }
            }
            return principal.getName();
        } catch (NamingException ex) {
            return principal.getName();
        }
    }

        /*
     * return email address of subject
     */
    public String getEmail() {

        X500Principal principal = x509Certificate.getSubjectX500Principal();
        try {
            LdapName ldapName = new LdapName(principal.toString());
            for (Rdn rdn : ldapName.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("emailaddress")) {
                    return rdn.getValue().toString();
                }
            }
            return principal.toString();
        } catch (NamingException ex) {
            return principal.toString();
        }
    }
}
