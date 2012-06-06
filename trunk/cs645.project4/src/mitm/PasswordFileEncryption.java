package mitm;

import java.io.*;
import java.security.*;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * CS645 Project 4<br>
 * Encrypted password file generator - encryption and decryption using
 * AES, secret key, salt and iterations.<br>
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
	private static final String DEFAULT_IN_PASSWORD_PLAIN_FILE = "./mitm_admin_passwords_plain.txt";
	private static final String DEFAULT_OUT_PASSWORD_ENC_FILE = "./mitm_admin_passwords_encrypted.txt";
	private static final String DELIMETER = " ";
	
	// cryptography definitions
	private static final String ALGORITHM = "AES";			// AES
	private static final byte[] SECRET_KEY = new byte[] {	// 128 bit key
		(byte) 0x98, (byte) 0xfe, (byte) 0x21, (byte) 0x76,
		(byte) 0xca, (byte) 0xd6, (byte) 0x45, (byte) 0x4b,
		(byte) 0xb6, (byte) 0x01, (byte) 0xf2, (byte) 0xe9,
		(byte) 0x3e, (byte) 0x1d, (byte) 0x74, (byte) 0x84
	};
	private static final int NUM_ITERATIONS = 3;			// iterations
	
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
	 * @see java.lang.Runnable#run()
	 * ================================================
	 */
	public void run() {
		// read the plaintext password file and extract
		// user, salt and password
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
		scan.nextLine();
		// read all entries
		List<String[]> data = new ArrayList<String[]>();
		while (scan.hasNext())
			data.add(scan.nextLine().split(DELIMETER));
		scan.close();
		
		// create encrypted passwords data
		String[] entry;
		String enc = null;
		String dec = null;
		for (int i = 0; i < data.size(); i++) {
			entry = data.get(i);
			System.out.println("Entry " + (i + 1) + ":");
			System.out.println("> username:           " + entry[0]);
			System.out.println("> salt:               " + entry[1]);
			System.out.println("> password:           " + entry[2]);
			try {
				enc = encrypt(entry[2], entry[1]);
			} catch (Exception e) {
				System.err.println("Error occurred during encryption.");
				e.printStackTrace();
				System.exit(0);
			}
			System.out.println("> encrypted password: " + enc);
			try {
				dec = decrypt(enc, entry[1]);
			} catch (Exception e) {
				System.err.println("Error occurred during decryption.");
				e.printStackTrace();
				System.exit(0);
			}
			System.out.println("> decrypted password: " + dec);
			System.out.println();
			entry[2] = enc;
		}
		
		// write to output file
		try {
			PrintWriter outWriter = new PrintWriter(new File(m_outputFilePath));
			// write header
			outWriter.println("USER SALT ENCRYPTED_PASSWORD");
			// write data
			for (int i = 0; i < data.size(); i++) {
				entry = data.get(i);
				outWriter.println(
						entry[0] + DELIMETER +
						entry[1] + DELIMETER +
						entry[2]);
			}
			outWriter.flush();
			outWriter.close();
			
		} catch (FileNotFoundException e) {
			System.err.println(
					"Error writing to output file: " + m_outputFilePath + "\n" +
					"Exiting.");
			e.printStackTrace();
			System.exit(0);
		}
	}
	
	
	/* =========
	 * Utilities
	 * =========
	 */
	
	// Encryption with salt and iterations
	public static String encrypt(String plaintext, String salt) throws Exception {
		// initialization
		Key key = genKey();
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		
		// encryption with salt and iterations
		byte[] encryptedBytes;
		String ciphertext = plaintext;
		sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
		for (int i = 0; i < NUM_ITERATIONS; i++) {
			encryptedBytes = cipher.doFinal((salt + ciphertext).getBytes());
			ciphertext = encoder.encode(encryptedBytes);
		}
		return ciphertext.replaceAll("\\r|\\n", "");
	}
	
	// Decryption with salt and iterations
	public static String decrypt(String ciphertext, String salt) throws Exception {
		// initialization
		Key key = genKey();
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, key);
		int saltLen = salt.length();
		
		// decryption with salt and iterations
		byte[] decryptedBytes;
		String plaintext = ciphertext;
		sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
		for (int i = 0; i < NUM_ITERATIONS; i++) {
			decryptedBytes = cipher.doFinal(decoder.decodeBuffer(plaintext));
			plaintext = new String(decryptedBytes).substring(saltLen);
		}
		return plaintext;
	}
	
	// Key generation
	private static Key genKey() throws Exception {
		Key key = new SecretKeySpec(SECRET_KEY, ALGORITHM);
		return key;
	}
}




























