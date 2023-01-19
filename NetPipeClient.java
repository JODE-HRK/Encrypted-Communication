import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;
    private  HandshakeMessage clientHello;
    private  HandshakeMessage fromServerHello;
    private  HandshakeMessage fromServerFinished;
    private  HandshakeMessage sessionPre;
    private  HandshakeMessage clientFinished;
    private  HandshakeMessage handshakeMessage;

    private  String ServerCertificate;
    private  HandshakeCertificate x509ServerCertificate;
    private  SessionKey sessionKey;
    private  SessionCipher sessionCipher;
    private  HandshakeDigest handshakeDigest;
    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "client certificate PEM file");
        arguments.setArgumentSpec("key", "client private key DER file");
        arguments.setArgumentSpec("cacert", "CA certificate PEM file");

        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    private  String encodeCertificate(String certificateFile) throws IOException, CertificateException {
        FileInputStream instream = new FileInputStream(certificateFile);
        HandshakeCertificate handshakeCertificate = new HandshakeCertificate(instream);
        byte[] certBytes = handshakeCertificate.getBytes();
        return Base64.getEncoder().encodeToString(certBytes);
    }

    private  void sendCertificate(String cerAddress, Socket socket) throws CertificateException, IOException {
        clientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        clientHello.putParameter("Certificate", encodeCertificate(cerAddress));
        clientHello.send(socket);

        System.out.println("ClientCertificate Sent!");
    }

    private  void receiveCertificate(Socket socket) throws CertificateException {
        String encodedCertificate = null;
        try {
            fromServerHello = HandshakeMessage.recv(socket);
            encodedCertificate = fromServerHello.getParameter("Certificate");
        }catch (Exception e){
            System.out.println("Get Certificate Error\n");
            System.exit(1);
        }

        ServerCertificate = encodedCertificate;
        x509ServerCertificate = new HandshakeCertificate(Base64.getDecoder().decode(ServerCertificate));

        System.out.println("ServerCertificate Received!");
    }

    private  void verifyCertificate(String caAddress) throws FileNotFoundException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        FileInputStream cainstream = new FileInputStream(caAddress);
        HandshakeCertificate CAHandshakeCertificate = new HandshakeCertificate(cainstream);
        x509ServerCertificate.verify(CAHandshakeCertificate);

        System.out.println("ServerCertificate verified!");
    }


    private  void sendSessionInformation(Socket socket) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        sessionPre = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        HandshakeCrypto sessionCrypto = new HandshakeCrypto(x509ServerCertificate);

        sessionKey = new SessionKey(128);
        byte[] sessionKeyEncrypted = sessionCrypto.encrypt(sessionKey.getKeyBytes());
        sessionPre.put("SessionKey", Base64.getEncoder().encodeToString(sessionKeyEncrypted));

        sessionCipher = new SessionCipher(sessionKey);
        byte[] sessionCipherEncrpted = sessionCrypto.encrypt(sessionCipher.getIVBytes());
        sessionPre.put("SessionIV", Base64.getEncoder().encodeToString(sessionCipherEncrpted));

        sessionPre.send(socket);

        System.out.println("SessionInformation sent!");
    }

    private  void receiveServerFinished(Socket socket) throws IOException, ClassNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        HandshakeCrypto finishedCrypto = new HandshakeCrypto(x509ServerCertificate);

        fromServerFinished = HandshakeMessage.recv(socket);
        String signatureEncryptedString = fromServerFinished.getParameter("Signature");
        byte[] signatureEncrypted = Base64.getDecoder().decode(signatureEncryptedString);
        byte[] digestSignature = finishedCrypto.decrypt(signatureEncrypted);
        byte[] timestampEncrypted = Base64.getDecoder().decode(fromServerFinished.getParameter("TimeStamp"));
        byte[] timestamp = finishedCrypto.decrypt(timestampEncrypted);

        verifyServerFinished(digestSignature, timestamp);
    }

    private  void verifyServerFinished(byte[] signature, byte[] timestamp) throws NoSuchAlgorithmException, IOException {
        handshakeDigest = new HandshakeDigest();
        byte[] originalSignature = fromServerHello.getBytes();
        handshakeDigest.update(originalSignature);
        byte[] verifyDigest = handshakeDigest.digest();
//        if (verifyDigest.equals(signature))
        if (Arrays.equals(verifyDigest, signature))
            System.out.println("ServerFinished Verified!");
        else{
            System.out.println("ServerFinished Verified Wrong!");
//            System.exit(1);
        }

        String stringOftime = new String(timestamp, StandardCharsets.US_ASCII);
        System.out.println(stringOftime + " ServerFinished Received!");
    }

    private  void sendClientFinished(Socket socket, String privateKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        clientFinished = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        handshakeDigest = new HandshakeDigest();
        FileInputStream keyInputStream = new FileInputStream(privateKey);
        byte[] keybytes = keyInputStream.readAllBytes();
        HandshakeCrypto finishedCrypto = new HandshakeCrypto(keybytes);

        byte[] clienthelloByte = clientHello.getBytes();
        byte[] sessionPreByte = sessionPre.getBytes();
        byte[] totalByte = new byte[clienthelloByte.length + sessionPreByte.length];
        System.arraycopy(clienthelloByte,0, totalByte, 0, clienthelloByte.length);
        System.arraycopy(sessionPreByte,0, totalByte, clienthelloByte.length, sessionPreByte.length);
        handshakeDigest.update(totalByte);
        byte[] digestSignature = handshakeDigest.digest();
        byte[] digestSignatureEncrypted = finishedCrypto.encrypt(digestSignature);
        String digestSignatureEncryptedString = Base64.getEncoder().encodeToString(digestSignatureEncrypted);
        clientFinished.putParameter("Signature", digestSignatureEncryptedString);

        SimpleDateFormat timeStampFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        String nowTime = timeStampFormat.format(timestamp);
        byte[] digestTimeStampEncrypted = finishedCrypto.encrypt(nowTime.getBytes(StandardCharsets.UTF_8));
        clientFinished.put("TimeStamp", Base64.getEncoder().encodeToString(digestTimeStampEncrypted));
        clientFinished.send(socket);

        System.out.println(nowTime + " ClientFinished Sent!");
    }

    public NetPipeClient(Socket socket) throws CertificateException, IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, InvalidKeySpecException {
        sendCertificate(arguments.get("usercert"), socket);
        receiveCertificate(socket);
        verifyCertificate(arguments.get("cacert"));

        sendSessionInformation(socket);

        receiveServerFinished(socket);
        sendClientFinished(socket, arguments.get("key"));
    }
    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, InvalidKeySpecException {
        Socket socket = null;

        parseArgs(args);

        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }

        NetPipeClient netPipeClient = new NetPipeClient(socket);


        SessionCipher sessionCipherEncrypt = new SessionCipher(netPipeClient.sessionCipher.getSessionKey(), netPipeClient.sessionCipher.getIVBytes());
        SessionCipher sessionCipherDecrypt = new SessionCipher(netPipeClient.sessionCipher.getSessionKey(), netPipeClient.sessionCipher.getIVBytes());

        try{
            OutputStream decryptedOutStream = sessionCipherDecrypt.openEncryptedOutputStream(socket.getOutputStream());
            InputStream encryptedInputStream = sessionCipherEncrypt.openDecryptedInputStream(socket.getInputStream());
            Forwarder.forwardStreams(System.in, System.out, encryptedInputStream, decryptedOutStream, socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }
}
