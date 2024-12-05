import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.logging.*;

public class RSAEncryption {

    private BigInteger n;
    private BigInteger e;
    private BigInteger d;
    private BigInteger V;

    public RSAEncryption(int bitlength) {
        BigInteger p = BigInteger.probablePrime(bitlength, new SecureRandom());
        BigInteger q = BigInteger.probablePrime(bitlength, new SecureRandom());
        n = p.multiply(q);
        V = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.valueOf(65537); 
        d = e.modInverse(V);
    }

    public BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    public BigInteger decrypt(BigInteger encrypted) {
        return encrypted.modPow(d, n);
    }

    public BigInteger encryptString(String message) {
        byte[] messageBytes = message.getBytes(); 
        BigInteger messageBigInt = new BigInteger(1, messageBytes); 
        return encrypt(messageBigInt);
    }

    public String decryptString(BigInteger encryptedMessage) {
        BigInteger decryptedBigInt = decrypt(encryptedMessage); 
        byte[] decryptedBytes = decryptedBigInt.toByteArray(); 
        return new String(decryptedBytes); 
    }

    public BigInteger getPublicKey() {
        return e;
    }

    public BigInteger getModulus() {
        return n;
    }

    public static void main(String[] args) {

        Logger logger = Logger.getLogger(RSAEncryption.class.getName());
        ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.INFO);
        logger.addHandler(consoleHandler);

        logger.setLevel(Level.INFO);

        Scanner scanner = new Scanner(System.in);
        RSAEncryption rsa = new RSAEncryption(1024);

        logger.info("Chiave pubblica (e): " + rsa.getPublicKey());
        logger.info("Modulo (n): " + rsa.getModulus());

        logger.info("Inserisci un messaggio numerico da criptare: ");
        BigInteger message = new BigInteger(scanner.nextLine());
        BigInteger encryptedMessage = rsa.encrypt(message);
        logger.info("Messaggio criptato: " + encryptedMessage);
        BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);
        logger.info("Messaggio decriptato: " + decryptedMessage);

        logger.info("Inserisci un messaggio (testo) da criptare: ");
        String textMessage = scanner.nextLine();
        BigInteger encryptedTextMessage = rsa.encryptString(textMessage);
        logger.info("Messaggio criptato (testo): " + encryptedTextMessage);
        String decryptedTextMessage = rsa.decryptString(encryptedTextMessage);
        logger.info("Messaggio decriptato (testo): " + decryptedTextMessage);

        scanner.close();
    }
}

