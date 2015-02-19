// jusan ng

import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
 
public class AES {
 
    private int pswdIterations = 65536;
    private int keySize = 128;
    private byte[] ivBytes;
    
    /**
     * Generate a salt value to diffuse the inputed password
     * @return a salt string
     * @throws UnsupportedEncodingException 
     */
    public byte[] generate_saltBytes() throws UnsupportedEncodingException {
    	return generateSalt().getBytes("UTF-8");
    }
    
    
    
    /**
     * 
     * @param plain_byte plainbyte
     * @param salt salt
     * @param password user input password
     * @return
     * @throws Exception
     */
    public byte[] encrypt_byte(byte[] plain_byte, byte[] salt, String password) throws Exception {      
        byte[] saltBytes = salt;
         
        // Derive the key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), 
                saltBytes, 
                pswdIterations, 
                keySize
        );
 
        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
 
        //encrypt the message
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters params = cipher.getParameters();
        ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedBytes = cipher.doFinal(plain_byte);
        
        return encryptedBytes;
    }   
    
    public byte[] encrypt_string(String plainText, byte[] salt, String password) throws Exception {   
    	byte[] saltBytes = salt; 
    	
        // Derive the key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), 
                saltBytes, 
                pswdIterations, 
                keySize
        );
 
        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
 
        //encrypt the message
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters params = cipher.getParameters();
        ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedTextBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        return encryptedTextBytes;
    }
 

    /**
     * 
     * @param encryptedBytes
     * @param spec
     * @param ivBytes
     * @return
     * @throws Exception
     */
    public byte[] decrypt_byte(byte[] encryptedBytes, String password, byte[] salt, byte[] incoming_ivBytes) throws Exception {
    	byte[] saltBytes = salt;
    	
        // Derive the key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), 
                saltBytes, 
                pswdIterations, 
                keySize
        );   
        
        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
 
        // Decrypt the message
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(incoming_ivBytes));
     
 
        byte[] decryptedBytes = null;
        try {
            decryptedBytes = cipher.doFinal(encryptedBytes);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
 
        return decryptedBytes;
    }

    /**
     * 
     * @param encryptedBytes
     * @return
     * @throws Exception
     */
    public byte[] decrypt_byte(byte[] encryptedBytes, byte[] salt, byte[] ivBytes, String password) throws Exception {
    	byte[] saltBytes = salt;
    	
        // Derive the key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), 
                saltBytes, 
                pswdIterations, 
                keySize
        );   
        
        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
 
        // Decrypt the message
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));
     
 
        byte[] decryptedBytes = null;
        try {
            decryptedBytes = cipher.doFinal(encryptedBytes);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
 
        return decryptedBytes;
    }

    
    public String decrypt_string(byte[] encryptedTextBytes, byte[] iv, byte[] salt, String password) throws Exception {
    	byte[] saltBytes = salt;
 
        // Derive the key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), 
                saltBytes, 
                pswdIterations, 
                keySize
        );
 
        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
 
        // Decrypt the message
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
     
 
        byte[] decryptedTextBytes = null;
        try {
            decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
 
        return new String(decryptedTextBytes);
    }
 
    public byte[] get_initialize_vector() {
    	return this.ivBytes;
    }
        
    private String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[20];
        random.nextBytes(bytes);
        String s = new String(bytes);
        return s;
    }
    
}
