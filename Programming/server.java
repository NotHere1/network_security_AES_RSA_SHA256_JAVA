// jusan ng

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;

/**
 * 
 */

/**
 * @author jusanng
 *
 */
public class server {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		int port = -1;
		ServerSocket listener = null;
		Socket client1_socket, client2_socket = null;
		String mode = "";
		
		if (args.length !=2)
		{
			System.out.println("Usage: Server <Port Number> <Trust/Not Trust Mode>");
			System.out.println("i.e. Server 12345 -t");
			System.exit(1);
		}
		else
		{
			try{
				port = Integer.parseInt(args[0]);
			}
			catch(NumberFormatException e){
				System.out.println("Port number must consist only of integers. "
						+ "Please try again");
				System.out.println("You entered [" + args[0] + "]");
				System.exit(1);
			}
			
			
			
			
			// check valid port # range
			if (port > 60000 || port < 1200) {
				System.out.println("Port # [" + port + "] must be within (1200,60000)");
				System.exit(1);
			}
			
			
			
			
			/**
			 * Mode 
			 */
			if (args[1].equalsIgnoreCase("-t")){
				mode = "trusted_mode";
			}
			// untrusted mode
			else if (args[1].equalsIgnoreCase("-u")){
				mode = "untrusted_mode";
			}
			else {
				System.out.println("Unknown mode. [" + args[1] + "]");
				System.out.println("Please enter only -u for untrusted_mode or -t for trusted_mode.");
				System.exit(0);
			}
		} // if args.len != 2		

		try {
			
		    /**
		     *  Server starts listening on port <port>
		     */
			listener = new ServerSocket(port);
			System.out.println("[" + mode + "] Server is listening on port: " 
					+ port);
			
			try {
				 
				// client2
				client2_socket = listener.accept(); // blocking method until client2 is made
				System.out.println("[" + mode + "]" + " Server just connected to: " + client2_socket.getRemoteSocketAddress());
				
				// client1
				client1_socket = listener.accept(); // blocking method until client1 is made
				System.out.println("[" + mode + "]" + " Server just connected to: " + client1_socket.getRemoteSocketAddress());
				
				// run communication process
				Client_Handler handler = new Client_Handler(client1_socket, client2_socket, mode);
				
				// mode
				if (mode.equalsIgnoreCase("trusted_mode")) {
					
					System.out.println("[trusted_mode] Sending untampered client1 data to client2");
					byte[] client1_data = handler.retrieve_data_from_client1();
					handler.send_data_to_client2(client1_data);
				
				}
				else if (mode.equalsIgnoreCase("untrusted_mode")) {
					
					System.out.println("[untrusted_mode] Sending serverdata to client2");
					handler.retrieve_data_from_client1();
					byte[] modified_client1_data = handler.replace_aes_encrypted_data_with_server_data();
					handler.send_data_to_client2(modified_client1_data);
				}
				
				// close off unclosed stream
				handler.close_indata_stream();
				
			}
			finally {
				System.out.println("Releasing port [" + port + "]");
				listener.close();
			}
		
		}
		catch(java.net.BindException e) {
			System.out.println("[Error] Port already in use. Choose another port.");
		}
		catch(FileNotFoundException e) {
			System.out.println("[Error] File serverdata no found");
		}
		catch(IOException e) {
			e.printStackTrace();
			System.err.println("IO Error");
		}
		finally {
			System.exit(0);
		}
		
	} // main
	
} // class server
