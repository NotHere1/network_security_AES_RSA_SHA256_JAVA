// jusan ng

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class Generate_RSA_Key_Pair {
	
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, Exception {

    	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom()); // generate RSA key pair using 2048 bits ~ exponent of 2048 bit! crazy
        KeyPair myPair = keyGen.genKeyPair();
        
        KeyFactory fact = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pub = fact.getKeySpec(myPair.getPublic(),
          RSAPublicKeySpec.class);
        RSAPrivateKeySpec priv = fact.getKeySpec(myPair.getPrivate(),
          RSAPrivateKeySpec.class);

        saveToFile("public.key", pub.getModulus(),
          pub.getPublicExponent());
        saveToFile("private.key", priv.getModulus(),
          priv.getPrivateExponent());
        
        
        /**
         * print out the keypair as byte array string
         */
//        byte[] publicKey = myPair.getPublic().getEncoded();
//        byte[] privateKey = myPair.getPrivate().getEncoded();
//        System.out.println(java.util.Arrays.toString(publicKey));
//        System.out.println("\n");
//        System.out.println(java.util.Arrays.toString(privateKey));

    }
    
    public static void saveToFile(String fileName,
    		  BigInteger mod, BigInteger exp) throws IOException {
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
   
} // main