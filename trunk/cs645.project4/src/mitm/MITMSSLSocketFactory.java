//Based on SnifferSSLSocketFactory.java from The Grinder distribution.
// The Grinder distribution is available at http://grinder.sourceforge.net/

package mitm;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.asn1.structures.RDN;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.math.BigInteger;


/**
 * MITMSSLSocketFactory is used to create SSL sockets.
 *
 * This is needed because the javax.net.ssl socket factory classes don't
 * allow creation of factories with custom parameters.
 *
 */
public final class MITMSSLSocketFactory implements MITMSocketFactory
{
	//TODO added signature algorithm for forgery
	private static final AlgorithmID DEFAULT_SIGNATURE_ALGORITHM = AlgorithmID.sha512WithRSAEncryption;
	
	final ServerSocketFactory m_serverSocketFactory;
	final SocketFactory m_clientSocketFactory;
	final SSLContext m_sslContext;

	public KeyStore ks = null;

	/*
	 *
	 * We can't install our own TrustManagerFactory without messing
	 * with the security properties file. Hence we create our own
	 * SSLContext and initialise it. Passing null as the keystore
	 * parameter to SSLContext.init() results in a empty keystore
	 * being used, as does passing the key manager array obtain from
	 * keyManagerFactory.getInstance().getKeyManagers(). To pick up
	 * the "default" keystore system properties, we have to read them
	 * explicitly. UGLY, but necessary so we understand the expected
	 * properties.
	 *
	 */

	/**
	 * This constructor will create an SSL server socket factory
	 * that is initialized with a fixed CA certificate
	 */
	public MITMSSLSocketFactory()
			throws IOException,GeneralSecurityException
			{
		m_sslContext = SSLContext.getInstance("SSL");

		final KeyManagerFactory keyManagerFactory =
				KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

		final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
		final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
		final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

		final KeyStore keyStore;

		if (keyStoreFile != null) {
			keyStore = KeyStore.getInstance(keyStoreType);
			keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

			this.ks = keyStore;
		} else {
			keyStore = null;
		}

		keyManagerFactory.init(keyStore, keyStorePassword);

		m_sslContext.init(keyManagerFactory.getKeyManagers(),
				new TrustManager[] { new TrustEveryone() },
				null);

		m_clientSocketFactory = m_sslContext.getSocketFactory();
		m_serverSocketFactory = m_sslContext.getServerSocketFactory();
			}

	/**
	 * This constructor will create an SSL server socket factory
	 * that is initialized with a dynamically generated server certificate
	 * that contains the specified common name.
	 */
	public MITMSSLSocketFactory(String remoteCN, BigInteger serialno)
			throws IOException,GeneralSecurityException, Exception
			{
		// *** START ***

		// initialize (like the default constructor)
		m_sslContext = SSLContext.getInstance("SSL");

		final KeyManagerFactory keyManagerFactory =
				KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

		final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
		final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
		final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");
		final String keyStoreAlias = System.getProperty(JSSEConstants.KEYSTORE_ALIAS_PROPERTY, JSSEConstants.DEFAULT_ALIAS);

		final KeyStore keyStore;

		if (keyStoreFile != null) {
			keyStore = KeyStore.getInstance(keyStoreType);
			keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

			this.ks = keyStore;
		} else {
			keyStore = null;
		}
		
		// start forgery - create new self-signed valid certificate

		// get stored certificate
		iaik.x509.X509Certificate storedCert =
				new iaik.x509.X509Certificate(keyStore.getCertificate(keyStoreAlias).getEncoded());
		// get private and public keys
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyStoreAlias, keyStorePassword);
		PublicKey publicKey = storedCert.getPublicKey();
		
		iaik.x509.X509Certificate forgedCert = new iaik.x509.X509Certificate();
		// name
		Name name = new Name();
		RDN rdn = new RDN(ObjectID.commonName, remoteCN);
		name.addRDN(rdn);
		forgedCert.setSubjectDN(name);
		// serial number
		forgedCert.setSerialNumber(serialno);
		// set stored certificate as issuer
		forgedCert.setIssuerDN(storedCert.getIssuerDN());
		// validity - timestamp from now to 2 years ahead
		Calendar calInst = Calendar.getInstance();
		forgedCert.setValidNotBefore(calInst.getTime());
		calInst.add(Calendar.YEAR,2);
		forgedCert.setValidNotAfter(calInst.getTime());

		// sign certificate
		forgedCert.setPublicKey(publicKey);
		forgedCert.sign(DEFAULT_SIGNATURE_ALGORITHM, privateKey);
		
		// update certificate and key entries in keystore
		//keyStore.setCertificateEntry(keyStoreAlias, forgedCert);
		keyStore.setKeyEntry(
				keyStoreAlias,
				privateKey,
				keyStorePassword,
				new Certificate[] {forgedCert});
		
		// update keystore
		keyManagerFactory.init(keyStore, keyStorePassword);

		m_sslContext.init(keyManagerFactory.getKeyManagers(),
				new TrustManager[] { new TrustEveryone() },
				null);

		m_clientSocketFactory = m_sslContext.getSocketFactory();
		m_serverSocketFactory = m_sslContext.getServerSocketFactory();
		
		// *** END ***
			}

	public final ServerSocket createServerSocket(String localHost,
			int localPort,
			int timeout)
					throws IOException
					{
		final SSLServerSocket socket =
				(SSLServerSocket)m_serverSocketFactory.createServerSocket(
						localPort, 50, InetAddress.getByName(localHost));

		socket.setSoTimeout(timeout);

		socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

		return socket;
					}

	public final Socket createClientSocket(String remoteHost, int remotePort)
			throws IOException
			{
		final SSLSocket socket =
				(SSLSocket)m_clientSocketFactory.createSocket(remoteHost,
						remotePort);

		socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

		socket.startHandshake();

		return socket;
			}

	/**
	 * We're carrying out a MITM attack, we don't care whether the cert
	 * chains are trusted or not ;-)
	 *
	 */
	private static class TrustEveryone implements X509TrustManager
	{
		public void checkClientTrusted(X509Certificate[] chain,
				String authenticationType) {
		}

		public void checkServerTrusted(X509Certificate[] chain,
				String authenticationType) {
		}

		public X509Certificate[] getAcceptedIssuers()
		{
			return null;
		}
	}
}

