// jusan ng

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.IllegalBlockSizeException;

/**
 * 
 */

/**
 * @author jusanng
 *
 */
public class client2 {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		int port = -1;
		String servername = "";
		Socket socket = null;
		OutputStream file_out = null;
		InputStream from_server = null;
		
		
		if (args.length != 2){
			System.out.println("Usage: client <server name> <port number>");
			System.exit(1);
		}
	
		try {
			port = Integer.parseInt(args[1]);
			servername = args[0];
			
			/*
			 *  check port validity
			 */
			if (port > 60000 || port < 1200) {
				System.out.println("Port # [" + port + "] must be within (1200,60000)");
				System.exit(0);
			}
			System.out.println("Establishing connection to host: [" + servername
					+ "] ,on port [" + port + "]");
			
			
			
			/*
			 * establishes a connection to the server
			 */
			socket = new Socket(servername, port);

			
			
			
			/*
			 * read in encrypted data send from server
			 */
			from_server = socket.getInputStream();
			ByteArrayOutputStream encrypted_data = new ByteArrayOutputStream(); 	// a buffer that store the read-in data into memory
			
			int nRead, nReadTotal = 0;
			byte[] data = new byte[16384];
			while ((nRead = from_server.read(data, 0, data.length)) != -1) { 	// block
				nReadTotal += nRead;
				encrypted_data.write(data, 0, nRead);
			}
			System.out.println("Received: [" + nReadTotal + "] bytes from server");
			from_server.close();
			encrypted_data.close();
			
			
			
			/*
			 * Create a copy of the received data in tmp_buff
			 */
			byte[] tmp_buff = encrypted_data.toByteArray();
			
			
			
			/*
			 * Splices the RSA headers from the received byte array (first 768 bytes of the buffer)
			 * [0 - 256] ~ rsa_salt, [257 - 512] ~ rsa_pwd, [512 - 768] ~ rsa_hash_sha256 
			 */
			byte[] rsa_salt = new byte[256];
			byte[] rsa_pwd = new byte[256];
			byte[] rsa_hash_sha256_signature = new byte[256]; 
			rsa_pwd = Arrays.copyOfRange(tmp_buff, 0, 256);
			rsa_salt = Arrays.copyOfRange(tmp_buff, 256, 512);
			rsa_hash_sha256_signature = Arrays.copyOfRange(tmp_buff, 512, 768);
			System.out.println("rsa_salt: " + rsa_salt.length);
			System.out.println("rsa_pwd: " + rsa_pwd.length);
			System.out.println("rsa_hash: " + rsa_hash_sha256_signature.length);
			


			/*
			 * Splices the AES's IV from the received byte array ( 769 - 784 )
			 */
			byte[] aes_iv = new byte[16];
			aes_iv = Arrays.copyOfRange(tmp_buff, 768, 784);
			System.out.println("iv: " + aes_iv.length);



			/*
			 * Splices the AES encrypted data from the copy-received buf 
			 * [769 - size of received data] ~ aes portion / actual data
			 */
			int aes_encrypted_data_size = tmp_buff.length - 784;
			byte[] aes_encrypted_data = new byte[aes_encrypted_data_size];
//			System.out.println("aes_encrypted_file b4 copy: " + aes_encrypted_data.length);
			aes_encrypted_data = Arrays.copyOfRange(tmp_buff, 784, tmp_buff.length);
//			System.out.println("aes_encrypted_file after copy: " + aes_encrypted_data.length);



			/*
			 * Check whether the receiving AES encrypted data file is multiple of 16
			 * If not, then file must be compromised or corrupted
			 */
			int aes_encrypted_file_size = aes_encrypted_data.length;
			if (aes_encrypted_file_size % 16 != 0) {
				System.out.println("[Warning] Received AES encrypted file size is not a multiple of 16.");
				System.out.println("[Warning] The file must be either compromised or corrupted.");
				System.exit(0);
			}
			


			/*
			 * Decrypts the spliced RSA headers
			 */
			byte[] decrpyted_aes_salt = RSA.rsaDecrypt(rsa_salt, "client2_private.key");
			byte[] decrpyted_aes_pwd = RSA.rsaDecrypt(rsa_pwd, "client2_private.key");
			byte[] decrpyted_hash_sha256_sig = RSA.rsaDecrypt(rsa_hash_sha256_signature, "client2_private.key");
			
			
			
			/*
			 * Decrypts AES encrypted data receives from server  
			 */
			AES d = new AES();
			String decrypted_pwd = new String(decrpyted_aes_pwd, "UTF-8");
			System.out.println("decrypted pwd is: " + decrypted_pwd);
			byte[] decrypted_aes_data = d.decrypt_byte(aes_encrypted_data, decrypted_pwd, decrpyted_aes_salt, aes_iv);
			
			
			
			/*
			 * Verifies Hash Sha-256 signature to check whether was data been tampered
			 */
			MessageDigest md = MessageDigest.getInstance("SHA-256");
 			md.update(decrypted_aes_data);
 			byte[] digest = md.digest();												// get the hash signature of received data
 			
 			if (MessageDigest.isEqual(digest, decrpyted_hash_sha256_sig)){
 				System.out.println("Verification Passed");
 			}
 			else {
 				System.out.println("Verification Failed");
 			}
 			
 			
 			
 			/*
 			 * Write aes decrypted data to local dir (regardless of tampering)
 			 */
 			file_out = new DataOutputStream(new FileOutputStream("client2data"));
 			ByteArrayInputStream decrypted_data = new ByteArrayInputStream(decrypted_aes_data);
 			
			nRead = nReadTotal = 0;
			data = new byte[16384];
			while ((nRead = decrypted_data.read(data, 0, data.length)) != -1) { 	// block
				nReadTotal += nRead;
				file_out.write(data, 0, nRead);
			}
			System.out.println("Decrypted file size is: [" + nReadTotal + "]");
 			
			file_out.close();
			decrypted_data.close();
			
		}
		catch (IllegalBlockSizeException e) {
			System.out.println("Received encrypted file is corrupted");
			System.exit(0);
		}
		catch (ArrayIndexOutOfBoundsException e) {
			System.out.println("Server unexpectedly closed");
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
		catch (IOException e) {
            System.out.println("Couldn't get I/O for " + "the connection to: " + servername);
            System.exit(0);
		}
		catch (NullPointerException e) {
			System.out.println("Received encrypted file is corrupted");
			System.exit(0);
		}
		catch (Exception e) {	
			e.printStackTrace();
			System.out.println("Fatal Error!");
			System.exit(0);
		}
		finally {
			
			System.out.println("Client2 Disconnected");
			
			if(socket !=null && from_server !=null && file_out !=null) {
   			 	try {
					socket.close();
					from_server.close();
					file_out.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		
		
	} // main
} // client
