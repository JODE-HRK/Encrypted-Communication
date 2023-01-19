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

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;
    private  HandshakeMessage serverHello;
    private  HandshakeMessage fromClientHello;
    private  HandshakeMessage fromSessionPre;
    private  HandshakeMessage serverFinished;
    private  HandshakeMessage fromClientFinished;
    private  HandshakeDigest handshakeDigest;

    private  String ClientCertificate;
    private  HandshakeCertificate x509ClientCertificate;
    private  HandshakeCertificate x509ServerCertificate;
    private  SessionKey sessionKey;
    private  SessionCipher sessionCipher;


    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--port=<portnumber>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
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

    private  void receiveCertificate(Socket socket) throws CertificateException {
        String encodedCertificate = null;
        try {
            fromClientHello = HandshakeMessage.recv(socket);
            encodedCertificate = fromClientHello.getParameter("Certificate");
        }catch (Exception e){
            System.out.println("Get Certificate Error\n");
            System.exit(1);
        }

        ClientCertificate = encodedCertificate;
        x509ClientCertificate = new HandshakeCertificate(Base64.getDecoder().decode(ClientCertificate));
        System.out.println(x509ClientCertificate.getCN());
//        System.out.println(ClientCertificate);

        System.out.println("ClientCertificate Received!");
    }

    private  String encodeCertificate(String certificateFile) throws IOException, CertificateException {
        FileInputStream instream = new FileInputStream(certificateFile);
        HandshakeCertificate handshakeCertificate = new HandshakeCertificate(instream);
        byte[] certBytes = handshakeCertificate.getBytes();
        return Base64.getEncoder().encodeToString(certBytes);
    }

    private  void sendCertificate(String cerAddress, Socket socket) throws CertificateException, IOException {
        serverHello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        serverHello.putParameter("Certificate", encodeCertificate(cerAddress));
        serverHello.send(socket);

        System.out.println("ServerCertificate sent!");
    }

    private  void verifyCertificate(String caAddress) throws FileNotFoundException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        FileInputStream cainstream = new FileInputStream(caAddress);
        HandshakeCertificate CAHandshakeCertificate = new HandshakeCertificate(cainstream);
        x509ClientCertificate.verify(CAHandshakeCertificate);

        System.out.println("ClientCertificate verified!");
    }

    private  void receiveSessionInformation(Socket socket, String privateKey) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        fromSessionPre = HandshakeMessage.recv(socket);
        FileInputStream keyInputStream = new FileInputStream(privateKey);
        byte[] keybytes = keyInputStream.readAllBytes();
        HandshakeCrypto sessionDecrypto = new HandshakeCrypto(keybytes);

        byte[] sessionKeyEncryptedByte = Base64.getDecoder().decode(fromSessionPre.getParameter("SessionKey"));
        byte[] sessionKeyByte = sessionDecrypto.decrypt(sessionKeyEncryptedByte);
        byte[] sessionIVEncryptedByte = Base64.getDecoder().decode(fromSessionPre.getParameter("SessionIV"));
        byte[] sessionIVByte = sessionDecrypto.decrypt(sessionIVEncryptedByte);

        sessionKey = new SessionKey(sessionKeyByte);
        sessionCipher = new SessionCipher(sessionKey, sessionIVByte);

        System.out.println("SessionInformation received!");
    }

    private  void sendServerFinished(Socket socket, String privateKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        serverFinished = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        handshakeDigest = new HandshakeDigest();
        FileInputStream keyInputStream = new FileInputStream(privateKey);
        byte[] keybytes = keyInputStream.readAllBytes();
        HandshakeCrypto finishedCrypto = new HandshakeCrypto(keybytes);

        byte[] signature = serverHello.getBytes();
        handshakeDigest.update(signature);
        byte[] digestSignature = handshakeDigest.digest();
        byte[] digestSignatureEncrypted = finishedCrypto.encrypt(digestSignature);
        String digestSignatureEncryptedString = Base64.getEncoder().encodeToString(digestSignatureEncrypted);
        serverFinished.putParameter("Signature", digestSignatureEncryptedString);

        SimpleDateFormat timeStampFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        String nowTime = timeStampFormat.format(timestamp);
        byte[] timestampByte = nowTime.getBytes(StandardCharsets.UTF_8);
        byte[] timestampByteEncrypted = finishedCrypto.encrypt(timestampByte);

        serverFinished.put("TimeStamp", Base64.getEncoder().encodeToString(timestampByteEncrypted));
        serverFinished.send(socket);

        System.out.println(nowTime + " ServerFinished Sent!");
    }

    private  void receiveClientFinished(Socket socket) throws IOException, ClassNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        HandshakeCrypto finishedCrypto = new HandshakeCrypto(x509ClientCertificate);

        fromClientFinished = HandshakeMessage.recv(socket);
        String digestSignatureEncryptedString = fromClientFinished.getParameter("Signature");
        byte[] digestSignatureEncrypted = Base64.getDecoder().decode(digestSignatureEncryptedString);
        byte[] digestSignature = finishedCrypto.decrypt(digestSignatureEncrypted);

        byte[] timestampEncrypted = Base64.getDecoder().decode(fromClientFinished.getParameter("TimeStamp"));
        byte[] timestamp = finishedCrypto.decrypt(timestampEncrypted);
        verifyClientFinished(digestSignature, timestamp);
    }

    private  void verifyClientFinished(byte[] signature, byte[] timestamp) throws NoSuchAlgorithmException, IOException {
        handshakeDigest = new HandshakeDigest();

        byte[] clienthelloByte = fromClientHello.getBytes();
        byte[] sessionPreByte = fromSessionPre.getBytes();
        byte[] totalByte = new byte[clienthelloByte.length + sessionPreByte.length];
        System.arraycopy(clienthelloByte,0, totalByte, 0, clienthelloByte.length);
        System.arraycopy(sessionPreByte,0, totalByte, clienthelloByte.length, sessionPreByte.length);
        handshakeDigest.update(totalByte);
        byte[] verifyDigest = handshakeDigest.digest();
        if (Arrays.equals(verifyDigest, signature))
            System.out.println("ClientFinished Verified!");
        else{
            System.out.println("ClientFinished Verified Wrong!");
//            System.exit(1);
        }

        String stringOftime = new String(timestamp, StandardCharsets.US_ASCII);
        System.out.println(stringOftime + " ClientFinished Received!");
    }

    public NetPipeServer(Socket socket) throws CertificateException, IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException, ClassNotFoundException, SignatureException, NoSuchProviderException {

        receiveCertificate(socket);
        verifyCertificate(arguments.get("cacert"));
        sendCertificate(arguments.get("usercert"), socket);

        receiveSessionInformation(socket, arguments.get("key"));

        sendServerFinished(socket, arguments.get("key"));
        receiveClientFinished(socket);
    }

    /*
     * Main program.
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main( String[] args) throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException {
        parseArgs(args);
        ServerSocket serverSocket = null;

        int port = Integer.parseInt(arguments.get("port"));
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.exit(1);
        }


        NetPipeServer netPipeServer = new NetPipeServer(socket);


        SessionCipher sessionCipherEncrypt = new SessionCipher(netPipeServer.sessionCipher.getSessionKey(), netPipeServer.sessionCipher.getIVBytes());
        SessionCipher sessionCipherDecrypt = new SessionCipher(netPipeServer.sessionCipher.getSessionKey(), netPipeServer.sessionCipher.getIVBytes());

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
