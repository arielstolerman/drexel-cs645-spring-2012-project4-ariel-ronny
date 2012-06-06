/**
 * CSE 490K Project 2
 */

package mitm;

import java.net.*;
import java.io.*;
import java.util.Scanner;
import java.util.regex.*;

import javax.net.ssl.SSLServerSocket;

// You need to add code to do the following
// 1) use SSL sockets instead of the plain sockets provided
// 2) check user authentication
// 3) perform the given administration command

class MITMAdminServer implements Runnable
{
	private static final String ADSERV_PREFIX = "[ADMIN_SERVER] "; //TODO for messages
	private SSLServerSocket m_serverSocket; //TODO changed from ServerSocket
	private Socket m_socket = null;
	private HTTPSProxyEngine m_engine;

	public MITMAdminServer( String localHost, int adminPort, HTTPSProxyEngine engine ) throws IOException {
		MITMPlainSocketFactory socketFactory =
				new MITMPlainSocketFactory();
		m_serverSocket = (SSLServerSocket) socketFactory.createServerSocket( localHost, adminPort, 0 ); //TODO added casting to SSLServerSocket
		m_engine = engine;
	}

	public void run() {
		System.out.println("Admin server initialized, listening on port " + m_serverSocket.getLocalPort());
		while( true ) {
			try {
				m_socket = m_serverSocket.accept();

				byte[] buffer = new byte[40960];

				Pattern userPwdPattern =
						Pattern.compile("username:(\\S+)\\s+password:(\\S+)\\s+command:(\\S+)\\sCN:(\\S*)\\s");

				BufferedInputStream in =
						new BufferedInputStream(m_socket.getInputStream(),
								buffer.length);
				
				PrintWriter socketWriter =
						new PrintWriter(m_socket.getOutputStream()); //TODO socket output-stream for messages
				
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
						socketWriter.println(ADSERV_PREFIX + "User " + userName + " authenticated"); // TODO added message
						String command = userPwdMatcher.group(3);
						//String commonName = userPwdMatcher.group(4); - unused

						doCommand( command );
					}
					// *** START *** TODO

					else {
						// report authentication failed
						socketWriter.println(ADSERV_PREFIX + "Authentication failed for user " + userName);
						// close socket
						m_socket.close();
					}
					socketWriter.close();

					// *** END ***
				}	
			}
			catch( InterruptedIOException e ) {
			}
			catch( Exception e ) {
				e.printStackTrace();
			}
		}
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
		PrintWriter socketWriter = new PrintWriter(m_socket.getOutputStream());
		
		// iterate over possible commands
		if (cmd.equals("shutdown")) {
			// shutdown MITM server
			socketWriter.println(ADSERV_PREFIX + "Shutting down MITM server");
			m_engine.shutdown();
		}
		else if (cmd.equals("stats")) {
			// List how many requests were proxied
			socketWriter.println(ADSERV_PREFIX + "Proxied requests: " +
					m_engine.getProxiedRequestsCount());
			
		}
		else {
			socketWriter.println(ADSERV_PREFIX + "Unrecognized command: " + cmd);
		}
		
		socketWriter.close();
		m_socket.close();
	}
	// *** END ***
}
