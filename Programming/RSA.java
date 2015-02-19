// jusan ng

/**
 * 
 */


import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author jusanng
 * Static Class for simple RSA Crypto-System
 */
public class RSA {

	
	/**
	 * Generates PKI RSA Key Pair
	 * @param RSA_key_len Key Length ~ 2048 recommended (valid as of Jan 2015)
	 * @return Generated KeyPair
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair generateRSAKeyPair(int RSA_key_len) throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    keyGen.initialize(RSA_key_len, new SecureRandom()); // generate RSA key pair using 2048 bits ~ exponent of 2048 bit! crazy
	    KeyPair myPair = keyGen.genKeyPair();
	    return myPair;
	}
	
	/**
	 * Save generated keyPair to specified file paths
	 * @param privateFilePath
	 * @param publicFilePath
	 * @param myPair
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public static void saveKeyPairToFile(String privateFilePath, String publicFilePath, KeyPair myPair) 
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		
		KeyFactory fact = KeyFactory.getInstance("RSA");
	    RSAPublicKeySpec pub = fact.getKeySpec(myPair.getPublic(),
	      RSAPublicKeySpec.class);
	    RSAPrivateKeySpec priv = fact.getKeySpec(myPair.getPrivate(),
	      RSAPrivateKeySpec.class);

	    saveToFile(publicFilePath, pub.getModulus(),
	      pub.getPublicExponent());
	    saveToFile(privateFilePath, priv.getModulus(),
	      priv.getPrivateExponent());
	}
    
	/**
	 * Internal Output File Descriptor method use by saveKeyPairToFile to
	 * @param fileName
	 * @param mod
	 * @param exp
	 * @throws IOException
	 */
    private static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
  		  ObjectOutputStream oout = new ObjectOutputStream(
  		    new BufferedOutputStream(new FileOutputStream(fileName)));
  		  try {
  		    oout.writeObject(mod);
  		    oout.writeObject(exp);
  		  } catch (Exception e) {
  		    throw new IOException("Unexpected error", e);
  		  } finally {
  		    oout.close();
  		  }
  		}
    
    /**
	 * RSA Decrypt using Private Key
	 * @param data
	 * @param privateKeyFilePath
	 * @return
     * @throws IOException 
     * @throws NoSuchPaddingException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
	 * @throws Exception
	 */
	public static byte[] rsaDecrypt(byte[] data, String privateKeyFilePath) 
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		byte[] decryptedData;
		
		try {
 		
		PrivateKey priKey = readPrivateKeyFromFile(privateKeyFilePath);
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, priKey);
		decryptedData = cipher.doFinal(data);
		
		} catch (IOException e) {
			throw new RuntimeException("PrivateKeyFile Not Found", e);
		}
		  
		return decryptedData;
	}
	
	/**
	 * RSA Encrypt using Public Key
	 * @param data
	 * @param publicKeyFilePath
	 * @return
	 * @throws IOException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws Exception
	 */
	public static byte[] rsaEncrypt(byte[] data, String publicKeyFilePath)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		byte[] encryptedData;
		
		try {  
				PublicKey pubKey = readPublicKeyFromFile(publicKeyFilePath);
		
				Cipher cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.ENCRYPT_MODE, pubKey);
				encryptedData = cipher.doFinal(data);			
		
		} catch (IOException e) {
			throw new RuntimeException("PublicKeyFile Not Found");
		}
				
		return encryptedData;
	}
	
	private static PrivateKey readPrivateKeyFromFile(String privateKeyFilePath) throws IOException {
		  java.io.InputStream in =
		     RSA.class.getResourceAsStream(privateKeyFilePath);
		  ObjectInputStream oin =
		    new ObjectInputStream(new BufferedInputStream(in));
		  try {
		    BigInteger m = (BigInteger) oin.readObject();
		    BigInteger e = (BigInteger) oin.readObject();
		    RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
		    KeyFactory fact = KeyFactory.getInstance("RSA");
		    PrivateKey priKey = fact.generatePrivate(keySpec);
		    return priKey;
		  } catch (NullPointerException e) {
			  throw new RuntimeException("PublicKeyFile Not Found", e);
		  } catch (Exception e) {
			  throw new RuntimeException("Spurious serialisation error", e);
		  } finally {
		    oin.close();
		  }
		}
	
	private static PublicKey readPublicKeyFromFile(String publicKeyFileName) throws IOException {
		  java.io.InputStream in =
		    RSA.class.getResourceAsStream(publicKeyFileName);
		  ObjectInputStream oin =
		    new ObjectInputStream(new BufferedInputStream(in));
		  try {
		    BigInteger m = (BigInteger) oin.readObject();
		    BigInteger e = (BigInteger) oin.readObject();
		    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
		    KeyFactory fact = KeyFactory.getInstance("RSA");
		    PublicKey pubKey = fact.generatePublic(keySpec);
		    return pubKey;
		  } catch (NullPointerException e) {
			  throw new RuntimeException("PublicKeyFile Not Found", e);
		  } catch (Exception e) {
			  throw new RuntimeException("Spurious serialisation error", e);
		  } finally {
		    oin.close();
		  }
		}
	
    
}
