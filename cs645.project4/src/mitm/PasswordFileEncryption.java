package mitm;

import java.io.*;
import java.security.*;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * CS645 Project 4<br>
 * Encrypted password file generator - encryption and decryption using
 * AES, secret key, salt and iterations.<br>
 * TODO add more description
 * Based on {@link http://www.digizol.org/2009/10/java-encrypt-decrypt-jce-salt.html}
 */
@SuppressWarnings("restriction")
public class PasswordFileEncryption implements Runnable {
	
	// default files
	// plaintext file format (header is disregarded)
	// USERNAME SALT PASSWORD
	// <username1> <salt1> <password1>
	// ...
	// <usernameN> <saltN> <passwordN>
	private static final String DEFAULT_IN_PASSWORD_PLAIN_FILE = "./mitm_admin_password_plain.txt";
	private static final String DEFAULT_OUT_PASSWORD_ENC_FILE = "./mitm_admin_password_encrypted.txt";
	private static final String DELIMETER = " ";
	
	// cryptography constants
	private static final String ENC_ALGORITHM = "AES";
	private static final byte[] ENC_SECRET_KEY = "RonnyAndAriel!!!".getBytes();
	private static final int ENC_NUM_ITERATIONS = 3;
	private static final String ENC_SALT = "MmmSalty";
	
	private static final String HMAC_ALGORITHM = "HmacSHA1";
	private static final byte[] HMAC_SECRET_KEY = "CS645-Forever!!!".getBytes();

	private static final String HASH_ALGORITHM = "SHA-1";
	private static final int HASH_NUM_ITERATIONS = 30;
	private static final String HASH_SALT = "ImSecure";
	
	// actual input / output files
	private String m_inputFilePath = DEFAULT_IN_PASSWORD_PLAIN_FILE;
	private String m_outputFilePath = DEFAULT_OUT_PASSWORD_ENC_FILE;
	
	/**
	 * Entry point for password file encryption.
	 * @param args
	 */
	public static void main(String[] args) {
		PasswordFileEncryption pfe = new PasswordFileEncryption(args);
		pfe.run();
	}
	
	// constructor with command line argument options
	public PasswordFileEncryption(String[] options) {
		String[] opArr;
		for (String option: options) {
			// check flag
			opArr = option.split("=");
			if (
					opArr.length != 2 ||
					(!opArr[0].equals("-input") && !opArr[0].equals("-output"))) {
				System.err.println("Invalid flag: " + option);
				printUsageAndExit();
			}
			if (!(new File(opArr[1])).exists()) {
				System.err.println("Invalid path: " + opArr[1]);
				printUsageAndExit();
			}
			// set flag
			if (opArr[0].equals("-input"))
				m_inputFilePath = opArr[1];
			else
				m_outputFilePath = opArr[1];
		}
	}
	
	// usage
	public void printUsage() {
		String usage = "Password file encryption usage:\n" +
						"-input=<input-file-path>        default: " + DEFAULT_IN_PASSWORD_PLAIN_FILE + "\n" +
						"-output=<output-file-path>      default: " + DEFAULT_OUT_PASSWORD_ENC_FILE + "\n" +
						"\n";
		System.out.println(usage);
	}
	
	public void printUsageAndExit() {
		printUsage();
		System.exit(0);
	}
	
	
	/* ================================================
	 * main code to encrypt the plaintext password file
	 * ================================================
	 */
	public void run() {
		System.out.println("Input (plaintext) password file:   " + m_inputFilePath);
		System.out.println("Output (ciphertext) password file: " + m_outputFilePath);
		System.out.println("Encryption algorithm:              " + ENC_ALGORITHM);
		System.out.println("Encryption secret-key:             " + new String(ENC_SECRET_KEY));
		System.out.println("Encryption number of iterations:   " + ENC_NUM_ITERATIONS);
		System.out.println("Encryption salt:                   " + ENC_SALT);
		System.out.println("HMAC algorithm:                    " + HMAC_ALGORITHM);
		System.out.println("HMAC secret-key:                   " + new String(HMAC_SECRET_KEY));
		System.out.println("Hash algorithm:                    " + HASH_ALGORITHM);
		System.out.println("Hash number of iterations:         " + HASH_NUM_ITERATIONS);
		System.out.println("Hash salt:                         " + HASH_SALT);
		System.out.println();
		
		// read the plaintext password file and extract
		// user and password
		Scanner scan = null;
		try {
			scan = new Scanner(new FileReader(m_inputFilePath));
		} catch (FileNotFoundException e) {
			System.err.println(
					"Error reading input file: " + m_inputFilePath + "\n" +
					"Exiting.");
			e.printStackTrace();
			System.exit(0);
		}
		// skip header line
		String plaintext = scan.nextLine();
		scan.close();
		System.out.println("Plaintext:  " + plaintext);
		
		// hash
		String hash = null;
		try {
			hash = hash(plaintext);
		} catch (Exception e) {
			System.err.println(
					"Error during hashing of plaintext: " + plaintext + "\n" +
					"Exiting.");
			e.printStackTrace();
			System.exit(0);
		}
		System.out.println("Hash:       " + hash);
		
		// encrypt
		String ciphertext = null;
		try {
			ciphertext = encrypt(hash);
		} catch (Exception e) {
			System.err.println(
					"Error during encryption of hash: " + hash + "\n" +
					"Exiting.");
			e.printStackTrace();
			System.exit(0);
		}
		System.out.println("Ciphertext: " + ciphertext);
		
		// write to output file
		try {
			PrintWriter outWriter = new PrintWriter(new File(m_outputFilePath));
			outWriter.println(ciphertext);
			outWriter.flush();
			outWriter.close();
			
		} catch (FileNotFoundException e) {
			System.err.println(
					"Error writing to output file: " + m_outputFilePath + "\n" +
					"Exiting.");
			e.printStackTrace();
			System.exit(0);
		}
		
		String dec = null;
		try {
			dec = decrypt(ciphertext);
		} catch (Exception e) {
			System.err.println(
					"Error during decryption of ciphertext: " + ciphertext + "\n" +
					"Exiting.");
			e.printStackTrace();
			System.exit(0);
		}
		System.out.println("Decryption process correctness: " + dec.equals(hash));
	}
	
	
	/* =========
	 * Utilities
	 * =========
	 */
	
	// Hash with salt and iterations + Hmac
	public static String hash(String plaintext) throws Exception {
		byte[] bytes = (HASH_SALT + plaintext).getBytes();
		// hash
		MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
		for (int i = 0; i < HASH_NUM_ITERATIONS; i++) {
			digest.reset();
			bytes = digest.digest(bytes);
		}
		// hmac
		Mac mac = Mac.getInstance(HMAC_ALGORITHM);
		Key key = genKey(HMAC_SECRET_KEY,HMAC_ALGORITHM);
		mac.init(key);
		sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
		return encoder.encode(mac.doFinal(bytes)).replaceAll("\\r|\\n", "");
	}
	
	// Encryption with salt and iterations
	public static String encrypt(String plaintext) throws Exception {
		// initialization
		Key key = genKey(ENC_SECRET_KEY, ENC_ALGORITHM);
		Cipher cipher = Cipher.getInstance(ENC_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		
		// encryption with salt and iterations
		byte[] encryptedBytes;
		String ciphertext = plaintext;
		sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
		for (int i = 0; i < ENC_NUM_ITERATIONS; i++) {
			encryptedBytes = cipher.doFinal((ENC_SALT + ciphertext).getBytes());
			ciphertext = encoder.encode(encryptedBytes);
		}
		return ciphertext.replaceAll("\\r|\\n", "");
	}
	
	// Decryption with salt and iterations
	public static String decrypt(String ciphertext) throws Exception {
		// initialization
		Key key = genKey(ENC_SECRET_KEY, ENC_ALGORITHM);
		Cipher cipher = Cipher.getInstance(ENC_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, key);
		int saltLen = ENC_SALT.length();
		
		// decryption with salt and iterations
		byte[] decryptedBytes;
		String plaintext = ciphertext;
		sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
		for (int i = 0; i < ENC_NUM_ITERATIONS; i++) {
			decryptedBytes = cipher.doFinal(decoder.decodeBuffer(plaintext));
			plaintext = new String(decryptedBytes).substring(saltLen);
		}
		return plaintext;
	}
	
	// Key generation
	private static Key genKey(byte[] secretKey, String algorithm) throws Exception {
		Key key = new SecretKeySpec(secretKey, algorithm);
		return key;
	}
}




























