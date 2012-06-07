/**
 * CSE 490K Project 2
 */

package mitm;

import java.net.*;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.regex.*;

import javax.net.ssl.SSLServerSocket;

// You need to add code to do the following
// 1) use SSL sockets instead of the plain sockets provided
// 2) check user authentication
// 3) perform the given administration command

class MITMAdminServer implements Runnable
{
	// *** START *** TODO
	// added fields
	private static final String ADSERV_PREFIX = "[ADMIN_SERVER] "; // for messages
	private static PrintWriter m_socketWriter; // for transferring messages to the admin client
	private SSLServerSocket m_serverSocket; // changed from ServerSocket
	private boolean m_shutdown = false;
	// *** END ***
	private Socket m_socket = null;
	private HTTPSProxyEngine m_engine;

	public MITMAdminServer( String localHost, int adminPort, HTTPSProxyEngine engine ) throws IOException {
		// *** START ***
		// changed to SSLSocketFactory
		try {
			MITMSSLSocketFactory socketFactory = new MITMSSLSocketFactory();
			m_serverSocket = (SSLServerSocket) socketFactory.createServerSocket( localHost, adminPort, 0 );
			m_engine = engine;
		} catch (GeneralSecurityException e) {
			System.err.println(ADSERV_PREFIX + "Failed to instantiate MITMSSLSocketFactory for MITMAdminServer");
			e.printStackTrace();
		}
		// *** END ***
	}

	public void run() {
		System.out.println("Admin server initialized, listening on port " + m_serverSocket.getLocalPort());
		while(!m_shutdown) {
			try {
				m_socket = m_serverSocket.accept();
				
				byte[] buffer = new byte[40960];

				Pattern userPwdPattern =
						Pattern.compile("username:(\\S+)\\s+password:(\\S+)\\s+command:(\\S+)\\s+CN:(\\S*)\\s+");

				BufferedInputStream in =
						new BufferedInputStream(m_socket.getInputStream(),
								buffer.length);
				
				// TODO for forwarding messages to the admin client
				m_socketWriter = new PrintWriter(m_socket.getOutputStream());
				
				// Read a buffer full.
				int bytesRead = in.read(buffer);

				String line = bytesRead > 0 ? new String(buffer, 0, bytesRead) : "";

				Matcher userPwdMatcher =
						userPwdPattern.matcher(line);

				// parse username and pwd
				if (userPwdMatcher.find()) {
					String userName = userPwdMatcher.group(1);
					String password = userPwdMatcher.group(2);

					// authenticate
					// if authenticated, do the command
					boolean authenticated = authenticate(userName, password);
					if( authenticated ) {
						String message = ADSERV_PREFIX + "User " + userName + " authenticated";
						System.out.println(message); // TODO added message
						m_socketWriter.println(message);
						m_socketWriter.flush();
						String command = userPwdMatcher.group(3);
						//String commonName = userPwdMatcher.group(4); - unused

						doCommand( command );
					}
					// *** START *** TODO

					else {
						// report authentication failed
						String message = ADSERV_PREFIX + "Authentication failed for user " + userName;
						System.out.println(message);
						m_socketWriter.println(message);
						m_socketWriter.flush();
						// close socket
						m_socket.close();
					}

					// *** END ***
				}	
			}
			catch( InterruptedIOException e ) {
			}
			catch( Exception e ) {
				e.printStackTrace();
			}
		}
		m_socketWriter.close();
	}

	// *** START *** TODO
	// added method for user authentication
	private boolean authenticate(String username, String password) {
		try {
			return (new PasswordFileEncryption()).authenticate(
					username, password, System.getProperty(JSSEConstants.CIPHERTEXT_PASSWORD_FILE_PROPERTY,
							JSSEConstants.CIPHERTEXT_PASSWORD_FILE_DEFAULT));
		} catch (Exception e) {
			System.err.println("Failed to authenticate.");
			e.printStackTrace();
			return false;
		}
	}
	
	// implemented the doCommand method
	private void doCommand( String cmd ) throws IOException {	
		cmd = cmd.toLowerCase();
		
		String message; 
		// iterate over possible commands
		if (cmd.equals("shutdown")) {
			// shutdown MITM server
			message = ADSERV_PREFIX + "Shutting down MITM server";
			System.out.println(message);
			m_socketWriter.println(message + ", see you later!");
			m_socketWriter.flush();
			m_engine.shutdown();
			m_shutdown = true;
		}
		else if (cmd.equals("stats")) {
			// List how many requests were proxied
			message = ADSERV_PREFIX + "Proxied requests: " +
					m_engine.getProxiedRequestsCount();
			System.out.println(message);
			m_socketWriter.println(message);
			m_socketWriter.flush();
		}
		else {
			message = ADSERV_PREFIX + "Unrecognized command: " + cmd;
			System.out.println(message);
			m_socketWriter.println(message);
			m_socketWriter.flush();
		}
		
		m_socket.close();
	}
	// *** END ***
}
