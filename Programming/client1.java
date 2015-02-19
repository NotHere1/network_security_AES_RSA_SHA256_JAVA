// jusan ng

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.util.regex.Pattern;


/**
 * @author jusanng
 *
 */
public class client1 {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		int port = -1;
		String servername = "";
		String pwd = "";
		String filepath = "";
		InputStream is = null;
		OutputStream toServer = null;
		Socket socket = null;
		int fileSize = 0;
	
		if (args.length != 4){
			System.out.println("Usage: client <server name> <port number> <pwd> <filename>");
			System.exit(0);
		}
	
		try {
			servername = args[0];
			port = Integer.parseInt(args[1]);
			pwd = args[2];
			filepath = args[3];
			
			// check port validity
			if (port > 60000 || port < 1200) {
				System.out.println("Port # [" + port + "] must be within (1200,60000)");
				System.exit(0);
			}
			
			// check pwd
			if (pwd.length() != 16) {
				System.out.println("Pwd length must be exactly 16 chars.");
				System.exit(0);
			}
			boolean hasValidChar = Pattern.matches("[a-zA-Z0-9<>;:\\|\\^!@#$%&_=+\"\'\\-\\[\\]\\(\\)\\*\\{\\}\\/\\\\]*", pwd);
			
			if (!hasValidChar) {
				System.out.println("Pwd has invalid characters");
				System.exit(0);
			}
			else
				System.out.println(pwd);
			
			
			System.out.println("Establishing connection to host: [" + servername
					+ "] ,on port [" + port + "]");
			
			
			
			/*
			 *  establishes a connection to the server
			 */
			socket = new Socket(servername, port);
			
			
			
			/*
			 *  checks and retrieves file into stack
			 */
			File file = new File(filepath);
			fileSize = (int) file.length();
			is = new FileInputStream(file);
			System.out.println("File size is: " + fileSize + " bytes");
			ByteArrayOutputStream unencrypted_data = new ByteArrayOutputStream(fileSize); 			// a buffer that store the read-in file in memory
			
			int nRead, nReadTotal = 0;
			byte[] buf = new byte[16384];
			while ((nRead = is.read(buf, 0, buf.length)) != -1) { 	// block
				nReadTotal += nRead;
				unencrypted_data.write(buf, 0, nRead);							
			}
			
			// check whether file read is successful
			if (fileSize != nReadTotal) {
				System.out.println("File read error. File size: " + fileSize + " != read in: " + nReadTotal);
				System.exit(0);
			}
			System.out.println("Read: " + nReadTotal + " bytes into memory");
			
			
			
			/*
			 * AES Encrypts Data 
			 */
			AES aes = new AES();
			byte[] aes_salt = aes.generate_saltBytes();														// get salt used to diffuse usr input key
			byte[] aes_encrypted_data = aes.encrypt_byte(unencrypted_data.toByteArray(), aes_salt, pwd);	// get encrypted data
			byte[] aes_cbc_iv = aes.get_initialize_vector();											// get iv used										
			
 			
 			
 			/*
 			 * Get SHA-256 Hash Signature of the Original File
 			 */
 			MessageDigest md = MessageDigest.getInstance("SHA-256");
 			md.update(unencrypted_data.toByteArray());
 			byte[] digest = md.digest();												// get the hash signature of orig file


 
 			/*
 			 * RSA Encrypt Data
 			 * Encrypts AES's pwd and salt, and the Hash-256 Signature of the original file
 			 */
 			byte[] rsa_encrypted_salt = RSA.rsaEncrypt(aes_salt, "client2_public.key");
			byte[] rsa_encrypted_pwd = RSA.rsaEncrypt(pwd.getBytes("UTF-8"), "client2_public.key");
			byte[] rsa_encrypted_hash_signature_digest = RSA.rsaEncrypt(digest, "client2_public.key");

			
		
			/*
			 * Total RSA header info size 256 * 3 = 768 bytes
			*/
			int rsaHeaderLen = rsa_encrypted_salt.length + rsa_encrypted_pwd.length + rsa_encrypted_hash_signature_digest.length;
			System.out.println("RSA salt bytes: " + rsa_encrypted_salt.length);	// 256
			System.out.println("RSA pwd bytes: " + rsa_encrypted_pwd.length);	// 256   
			System.out.println("RSA hash bytes: " + rsa_encrypted_hash_signature_digest.length);	// 256
			System.out.println("RSA header bytes: " + rsaHeaderLen);	// 768
			
			if (rsaHeaderLen != 768) {
				System.out.println("[Failed] RSA Header Encryption Error. RSA Header Packet size != 768");
				System.exit(0);
			}

			
			
			/*
			 * Check AES's IV
			 * AES's IV for 128 bits encryption is always 16 Bytes (to XOR 16 individual 4 unique 4 bytes blocks 128-bits-AES)
			 */
			if (aes_cbc_iv.length != 16) {
				System.out.println("AES IV bytes greater than 16 bytes. Please use 128 bits AES encryption.");
				System.exit(0);
			}
			System.out.println("AES's IV bytes: " + aes_cbc_iv.length);	// 16
			System.out.println("RSA Header + AES Iv len: " + (rsaHeaderLen + aes_cbc_iv.length));	// 784

	
			
			/*
			 * AES encrypted data size (varies based on input file size)
			 */
			System.out.println("AES encrypted file: [" + filepath  + "] size is: [" + aes_encrypted_data.length + "] bytes");
			
			
			
			/*
			 * Create a buffer that hold all the encrypted (RSA/AES/IV) data that needed to be transmitted over to server 
			 */
			ByteArrayOutputStream encrypted_data_to_server = new ByteArrayOutputStream();
			
			// append the RSA encrypted data to the buf to be sent over to server [RSA OFFSET 0 - 768]
			encrypted_data_to_server.write(rsa_encrypted_pwd); /* 0 - 256 bytes offset */
			encrypted_data_to_server.write(rsa_encrypted_salt); /* 257 - 512 bytes offset */
			encrypted_data_to_server.write(rsa_encrypted_hash_signature_digest); /* 513 - 768 offset */
			System.out.println("salt + pwd + hash: " + encrypted_data_to_server.size());
			
			// append the AES Initialize Vector  [AES OFFSET 769 - 784]
			encrypted_data_to_server.write(aes_cbc_iv); 
			System.out.println("salt + pwd + hash + IV: " + encrypted_data_to_server.size());	// 16
			
			// append the AES encrypted data to the buf to be sent over to server [AES OFFSET 785 - ]
			encrypted_data_to_server.write(aes_encrypted_data);
			System.out.println("salt + pwd + hash + IV + aes_encrypted_data: " + encrypted_data_to_server.size());
			
			byte[] encrypted_data = encrypted_data_to_server.toByteArray( );	// final buf to send over to server



			/*
			 * Check final output size against actual encrypted data size
			 */
			int actual_encrypted_data_size = rsaHeaderLen + aes_encrypted_data.length + aes_cbc_iv.length;
			if (actual_encrypted_data_size == encrypted_data.length)
				System.out.println("[Success] Encrypted data size to be sent over to server is: [" + encrypted_data.length + "]");
			else {
				System.out.println("[Failed] Encrypted data size: [" + encrypted_data.length + "] to be sent over to server is different from actual data size: [" + actual_encrypted_data_size + "]");
				System.exit(0);
			}
			
			
			
			/*
			 * sends encrypted data to server
			 */
			ByteArrayInputStream data_to_server = new ByteArrayInputStream(encrypted_data);
			toServer = socket.getOutputStream(); 					// a pipe to the server
			nRead = nReadTotal = 0; 
			buf = new byte[16384];
			while ((nRead = data_to_server.read(buf, 0, buf.length)) != -1) { 	// block
				nReadTotal += nRead;
				toServer.write(buf, 0, nRead);							
			}
			System.out.println("Send: [" + nReadTotal + "] bytes to server");
			System.out.println("Client1 Disconnect");
			
			
			
		}catch(NullPointerException e) {
			System.out.println("NullPointerException");
			e.printStackTrace();
			System.exit(0);
		}
		catch (NumberFormatException e) {
			System.out.println("Port number must consist only of integers.\n" +
					"Please try again");
			System.exit(0);
		}
		catch (UnknownHostException e) {
            System.out.println("Unknown host: " + servername);
            System.exit(0);
		}
		catch (FileNotFoundException e) {
			System.out.println("File not found: " + filepath);
			System.exit(0);
		}
		catch (java.net.ConnectException e) {
			System.out.println("Unreachable port: " + port);
			System.exit(0);
		}
		catch (IOException e) {
            System.out.println("Couldn't get I/O for " + "the connection to: " + servername);
            e.printStackTrace();
            System.exit(0);
		}
		catch (Exception e) {	
			e.printStackTrace();
			System.out.println("Fatal Error!");
			System.exit(0);
		}
		finally {
			
			if(socket !=null && is != null && toServer !=null) {
   			 	try {
					socket.close();
					is.close();
					toServer.close();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			
			System.exit(0);
		}
		
	} // main
} // client
