// jusan ng

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.Arrays;


/**
 * 
 * @author jusanng
 *
 */
public class Client_Handler {
	
	// fields
	private Socket client1_socket, client2_socket;
	private ByteArrayOutputStream in_data;
	private String mode;
	
	/**
	 * Constructor for Client_Handler class
	 * @param socket - connecting socket
	 */
	public Client_Handler(Socket client1, Socket client2, String mode) {
		
		this.client1_socket = client1;
		this.client2_socket = client2;
		this.mode = mode;
	}
	
	/**
	 * retrieves data from client 1
	 * @return data sent by client 1
	 * @throws IOException 
	 */
	public byte[] retrieve_data_from_client1() throws IOException {
		
		// read in the data from client 1
		InputStream from_client1 = client1_socket.getInputStream();
		in_data = new ByteArrayOutputStream();
		
		int nRead, nReadTotal = 0;
		byte[] buf = new byte[16385];
		
		while((nRead = from_client1.read(buf, 0, buf.length)) != -1) {
			nReadTotal += nRead;
			in_data.write(buf, 0, nRead);
		}
		println("Server received " + nReadTotal + " bytes from Client1.");
				
		from_client1.close();
		
		return in_data.toByteArray();
	}
	
	
	/**
	 * send data to client 2
	 * @throws IOException
	 */
	public void send_data_to_client2(byte[] data) throws IOException {
			
		OutputStream to_client2 = client2_socket.getOutputStream();
		ByteArrayInputStream out_data = new ByteArrayInputStream(data);
		
		int nRead, nReadTotal = 0;
		byte[] buf = new byte[16385];
		
		while((nRead = out_data.read(buf, 0, buf.length)) != -1) {
			nReadTotal += nRead;
			to_client2.write(buf, 0, nRead);
		}
		println("Server send " + nReadTotal + " bytes to Client2.");
		
		to_client2.close();
		out_data.close();
	}
	
	
	/**
	 * 
	 * @return
	 */
	public byte[] retrieve_salt_from_data() {

		byte[] data = in_data.toByteArray();
		
		byte[] rsa_salt = new byte[256];
		rsa_salt = Arrays.copyOfRange(data, 256, 512);

		return rsa_salt;
	}
	
	public byte[] retrieve_pwd_from_data() {
		
		byte[] data = in_data.toByteArray();
		
		byte[] rsa_pwd = new byte[256]; 
		rsa_pwd = Arrays.copyOfRange(data, 0, 256);
		
		return rsa_pwd;
	}
	
	
	/**
	 * 
	 * @return
	 */
	public byte[] retrieve_signature_from_data() {
		
		byte[] data = in_data.toByteArray();
		
		byte[] rsa_hash_sha256_signature = new byte[256]; 
		rsa_hash_sha256_signature = Arrays.copyOfRange(data, 512, 768);
		
		return rsa_hash_sha256_signature;
	}
	
	/**
	 * 
	 * @return
	 */
	public byte[] retrieve_iv_from_data() {
		
		byte[] data = in_data.toByteArray();
		
		byte[] aes_iv = new byte[16];
		aes_iv = Arrays.copyOfRange(data, 768, 784);
		
		return aes_iv;
	}
		
	
	/**
	 * retrieve the aes encrypted data from data received from client 1
	 * @param data data received from client 1
	 * @return aes portion of the received data
	 */
	public byte[] retrieve_aes_encryption_data() {

		byte[] data = in_data.toByteArray();
		
		int aes_encrypted_data_size = data.length - 784;
		byte[] aes_encrypted_data = new byte[aes_encrypted_data_size];
		aes_encrypted_data = Arrays.copyOfRange(data, 784, data.length);
		
		return aes_encrypted_data;
	}
	
	/**
	 * 
	 * @return
	 */
	public byte[] retrieve_rsa_and_iv_header() {
		
		byte[] data = in_data.toByteArray();
		
		byte[] rsa_and_iv_header = new byte[784];
		rsa_and_iv_header = Arrays.copyOfRange(data, 0, 784);
		
		return rsa_and_iv_header;
	}
	
	
	/**
	 * @throws IOException 
	 * 
	 */
	public byte[] replace_aes_encrypted_data_with_server_data() throws IOException {
		
		/*
		 *  checks and retrieves server data from local dir
		 */
		File file = new File("serverdata");
		int fileSize = (int) file.length();
		FileInputStream is = new FileInputStream(file);
		println("File size is: " + fileSize + " bytes");
		ByteArrayOutputStream filedata = new ByteArrayOutputStream(fileSize);
		
		int nRead, nReadTotal = 0;
		byte[] buf = new byte[16384];
		while ((nRead = is.read(buf, 0, buf.length)) != -1) { 	// block
			nReadTotal += nRead;
			filedata.write(buf, 0, nRead);							
		}
		is.close();
		
		// check whether file read is successful
		if (fileSize != nReadTotal) {
			System.out.println("File read error. File size: " + fileSize + " != read in: " + nReadTotal);
			System.exit(0);
		}
		println("Serverdata size is: [" + nReadTotal + "] bytes");
		
		// concatenate serverdata from file with signature
		byte[] serverdata = filedata.toByteArray();
		byte[] rsa_iv_header = retrieve_rsa_and_iv_header();
		println("Original signature header size is: [" + rsa_iv_header.length + "] bytes");
		
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream(); 
		bos.write(rsa_iv_header);
		bos.write(serverdata);
		byte[] modified_client1_data = bos.toByteArray();
		
		System.out.println("Serverdata + original signature size is: [" + (rsa_iv_header.length + nReadTotal) + "] bytes");
		
		return modified_client1_data;
	}
	
	/**
	 * 
	 * @throws IOException
	 */
	public void close_indata_stream() throws IOException {
		in_data.close();
	}
	
	/**
	 * 
	 * @param msg
	 */
	private void println(String msg) {
		System.out.println("[" + mode + "] " + msg);
	}
	
} // main
