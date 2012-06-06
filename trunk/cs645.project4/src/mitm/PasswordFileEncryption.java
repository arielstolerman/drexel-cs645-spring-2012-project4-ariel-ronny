package mitm;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;

import javax.crypto.Cipher;

/*
 * Keystore generated with:
 * > keytool -genkey -alias mykey -keysize 2048 -keypass falafel4u -storetype JKS -keyalg RSA -keystore mitm_keystore -validity 365
 */
@SuppressWarnings("restriction")
public class PasswordFileEncryption {

	private static final int DEFAULT_KEYSIZE =		2048;
	private static final String DEFAULT_ENC_ALGORITHM = "RSA";
	private static final String DEFAULT_KEYSTORE_FILE = "AdminServerStore";
	private static final String DEFAULT_KEYSTORE_TYPE = "JKS";
	private static final String PLAINTEXT_PASSWORD_FILE = "mitm_admin_passwords.txt";
	private static final String DELIM = " ";
	
	private static final String DEFAULT_SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
	private static final String DEFAULT_HASH_ALGORITHM = "SHA-1";
	
	private static final sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
	private static final sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
	
	// main for password file creation
	public static void main(String[] args) {
		// partially taken from MITMProxyServer:
		boolean gotPassphrase = false;
		try {
			for (int i=0; i<args.length; i++)
			{
				if (args[i].equalsIgnoreCase("-keyStore")) {
					System.setProperty(JSSEConstants.KEYSTORE_PROPERTY,
							args[++i]);
				} else if (args[i].equalsIgnoreCase("-keyStorePassword")) {
					System.setProperty(
							JSSEConstants.KEYSTORE_PASSWORD_PROPERTY,
							args[++i]);
					gotPassphrase = true;
				} else if (args[i].equalsIgnoreCase("-keyStoreType")) {
					System.setProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY,
							args[++i]);
				} else if (args[i].equalsIgnoreCase("-keyStoreAlias")) {
					System.setProperty(JSSEConstants.KEYSTORE_ALIAS_PROPERTY,
							args[++i]);
				} else if( args[i].equalsIgnoreCase("-pwdFile")) {
					System.setProperty(JSSEConstants.CIPHERTEXT_PASSWORD_FILE_PROPERTY,
							args[++i]);
				} else {
					// bad usage
					throw new Exception();
				}
			}
			if (!gotPassphrase)
				throw new Exception();
		} catch (Exception e) {
			usageAndExit();
		}
		
		new PasswordFileEncryption().run();
	}
	
	// printing usage
	public static void usageAndExit() {
		System.err.println("Error! invalid arguments. Usage:\n" +
						"[-keyStore <Keystore file>]                default: " + DEFAULT_KEYSTORE_FILE + "\n" +
						"-keyStorePassword <passphrase>\n" +
						"[-keyStoreType <keystore type>]            default: " + DEFAULT_KEYSTORE_TYPE + "\n" +
						"[-keyStoreAlias <keystore alias>]          default: " + JSSEConstants.DEFAULT_ALIAS + "\n" +
						"[-pwdFile <output encrypted password file> default: " + JSSEConstants.CIPHERTEXT_PASSWORD_FILE_DEFAULT + "\n"
				);
		
	}
	
	// constructor
	public PasswordFileEncryption() {}
	
	private String m_keystoreFile;
	private String m_kestorePass;
	private String m_keystoreType;
	private String m_keystoreAlias;
	private String m_outEncPassFile;
	
	private KeyStore m_keyStore = null;
	private KeyPair m_keyPair = null;
	
	public void run() {
		// get keystore properties
		m_keystoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY,
				DEFAULT_KEYSTORE_FILE);
		m_kestorePass = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY,
				"");
		m_keystoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY,
				DEFAULT_KEYSTORE_TYPE);
		m_keystoreAlias = System.getProperty(JSSEConstants.KEYSTORE_ALIAS_PROPERTY,
				JSSEConstants.DEFAULT_ALIAS);
		m_outEncPassFile = System.getProperty(JSSEConstants.CIPHERTEXT_PASSWORD_FILE_PROPERTY,
				JSSEConstants.CIPHERTEXT_PASSWORD_FILE_DEFAULT);
		
		// load keystore
		try {
			loadKeyStore();
		} catch (Exception e) {
			System.err.println("Error loading keystore.");
			e.printStackTrace();
			System.exit(0);
		}
		
		// get keypair
		try {
			getKeyPair();
		} catch (Exception e) {
			System.err.println("Error retrieving key pair from keystore.");
			e.printStackTrace();
			System.exit(0);
		}
		
		// read plaintext file
		Map<String, String> data = null;
		try {
			data = readPlainFile();
		} catch (Exception e) {
			System.err.println("Error reading plaintext password file " + PLAINTEXT_PASSWORD_FILE + ".");
			e.printStackTrace();
			System.exit(0);
		}
		
		// add individual random salts to each user-pass pair
		Map<String,Pair<String,String>> saltyData = null;
		try {
			saltyData = season(data);
		} catch (Exception e) {
			System.err.println("Error adding salts.");
			e.printStackTrace();
			System.exit(0);
		}
		
		// hash passwords using salts
		try {
			hash(saltyData);
		} catch (Exception e) {
			System.err.println("Error hashing.");
			e.printStackTrace();
			System.exit(0);
		}
		
		// serialize map to stream of bytes
		byte[] serialized = null;
		try {
			serialized = serializeToBytes(saltyData);
		} catch (Exception e) {
			System.err.println("Error serializing salted-hashed-map.");
			e.printStackTrace();
			System.exit(0);
		}
		
		// encrypt with public key
		String encrypted = null;
		try {
			encrypted = encrypt(serialized);
		} catch (Exception e) {
			System.err.println("Error encrypting serialized map.");
			e.printStackTrace();
			System.exit(0);
		}
		
		// finally, write to output file
		try {
			writeToFile(encrypted);
		} catch (Exception e) {
			System.err.println("Failed writing encrypted file.");
			e.printStackTrace();
			System.exit(0);
		}
	}
	
	// keystore loader
	public void loadKeyStore() throws Exception {
		if (!new File(m_keystoreFile).exists())
			throw new Exception();
		// load keystore file
		FileInputStream in = new FileInputStream(m_keystoreFile);
		m_keyStore = KeyStore.getInstance(m_keystoreType);
		m_keyStore.load(in, m_kestorePass.toCharArray());
	}
	
	// get key pair
	public void getKeyPair() throws Exception {
		// get private key
		PrivateKey privateKey = (PrivateKey) m_keyStore.getKey(
				m_keystoreAlias, m_kestorePass.toCharArray());
		Certificate certificate = m_keyStore.getCertificate(m_keystoreAlias);
		PublicKey publicKey = certificate.getPublicKey();
		m_keyPair = new KeyPair(publicKey, privateKey);
	}
	
	// read plaintext password file
	public Map<String,String> readPlainFile() throws Exception {
		Map<String,String> data = new HashMap<String,String>();
		Scanner scan = new Scanner(new File(PLAINTEXT_PASSWORD_FILE));
		String[] lineSplit;
		while (scan.hasNext()) {
			lineSplit = scan.nextLine().split(DELIM);
			if (lineSplit.length != 2)
				throw new Exception();
			data.put(lineSplit[0], lineSplit[1]);
		}
		return data;
	}
	
	// individually salt each user-pass pair
	public Map<String,Pair<String,String>> season(Map<String,String> data) throws Exception {
		Map<String,Pair<String,String>> saltyData = 
				new HashMap<String,Pair<String,String>>();
		
		// initialize secure random for salting
		SecureRandom rng = SecureRandom.getInstance(DEFAULT_SECURE_RANDOM_ALGORITHM);
		byte[] randSalt = new byte[4];
		// create salty data
		for (String key: data.keySet()) {
			rng.nextBytes(randSalt);
			saltyData.put(
					key,
					new Pair<String,String>(
							encoder.encode(randSalt).replaceAll("\\n|\\r", ""),
							data.get(key)));
		}
		return saltyData;
	}
	
	// substitute the passwords with hashes
	public void hash(Map<String,Pair<String,String>> saltyData) throws Exception {
		// init hash
		MessageDigest digest = MessageDigest.getInstance(DEFAULT_HASH_ALGORITHM);
		Pair<String,String> value;
		byte[] salt;
		byte[] pass;
		byte[] saltAndPass;
		byte[] hash;
		for (String key: saltyData.keySet()) {
			value = saltyData.get(key);
			salt = decoder.decodeBuffer(value.first);
			pass = value.second.getBytes();
			saltAndPass = new byte[salt.length + pass.length];
			int i = 0;
			for (; i < salt.length; i++)
				saltAndPass[i] = salt[i];
			for (; i < salt.length + pass.length; i++)
				saltAndPass[i] = pass[i - salt.length];
			hash = digest.digest(saltAndPass);
			value.second = encoder.encode(hash).replaceAll("\\n|\\r", "");
		}
	}
	
	// create stream of bytes from map
	public byte[] serializeToBytes(Object obj) throws Exception {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput out = new ObjectOutputStream(bos);   
		out.writeObject(obj);
		byte[] bytes = bos.toByteArray();
		out.close();
		bos.close();
		return bytes;
	}
	
	// encrypt stream of bytes
	public String encrypt(byte[] plainBytes) throws Exception {
		Cipher cipher = Cipher.getInstance(DEFAULT_ENC_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, m_keyPair.getPublic());
		byte[] cipherBytes = cipher.doFinal(plainBytes);
		return encoder.encode(cipherBytes).replaceAll("\\r|\\n", "");
	}
	
	// write to file
	public void writeToFile(String text) throws Exception {
		BufferedWriter bw = new BufferedWriter(new FileWriter(m_outEncPassFile));
		bw.write(text);
		bw.flush();
		bw.close();
	}
	
	// for holding pairs
	public static class Pair<T,E> {
		protected T first;
		protected E second;
		
		public Pair(T first, E second) {
			this.first = first;
			this.second = second;
		}
	}
}
























