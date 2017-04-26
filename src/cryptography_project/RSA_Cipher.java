package cryptography_project;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/*
Author: Joshua Insel

RSA and RSA-OAEP (Optimal Asymmetric Encryption Padding) in Java
Source: PKCS #1 v2.2
*/

public class RSA_Cipher {
   private final SHA_256 sha256 = new SHA_256();
   private final int hLen = 32;
   
   public RSA_Cipher(){}
   
   public byte[] encrypt(byte[] plainText, RSA_PublicKey publicKey) { //RSA encryption
       BigInteger message = new BigInteger(plainText);
       BigInteger n = publicKey.getModulus(); //RSA Modulus
       BigInteger e = publicKey.getPublicExponent(); //RSA Public Exponent
       if (message.compareTo(n) >= 0) {
           throw new InvalidDataException();
       }
       byte[] cipherText = message.modPow(e, n).toByteArray(); //Encryption
       return cipherText;
   }
   
   public byte[] decrypt(byte[] cipherText, RSA_PrivateKey privateKey) { //RSA decryption
       BigInteger message = new BigInteger(cipherText);
       BigInteger n = privateKey.getModulus(); //RSA Modulus
       BigInteger d = privateKey.getPrivateExponent(); //RSA Private Exponent
       if (message.compareTo(n) >= 0) {
           throw new InvalidDataException();
       }
       byte[] plainText = message.modPow(d, n).toByteArray(); //Decryption
       return plainText;
   }
   
   private byte[] mgf(byte[] mgfSeed, int maskLen) { //Mask generation function 
       byte[] t;
       ByteBuffer buffer1;
       ByteBuffer buffer2 = ByteBuffer.allocate(hLen * ((maskLen - 1)/hLen + 1));
       for (int counter = 0; counter < (maskLen - 1)/hLen + 1; counter++) {
           buffer1 = ByteBuffer.allocate(mgfSeed.length + 4);
           buffer1.put(mgfSeed);
           buffer1.putInt(counter);
           buffer2.put(sha256.digest(buffer1.array()));
       }
       t = buffer2.array();
       byte[] mask = new byte[maskLen];
       System.arraycopy(t, 0, mask, 0, maskLen);
       return mask;
   }
   
   public byte[] encryptOAEP(byte[] plainText, byte[] label, RSA_PublicKey publicKey) { //RSA-OAEP encryption
       int k; //Length of modulus in bytes
       if (publicKey.getModulus().bitLength() % 8 > 0) {
           k = publicKey.getModulus().bitLength()/8 + 1;
       }
       else {
           k = publicKey.getModulus().bitLength()/8;
       }
       if (plainText.length > k - 2*hLen - 2) {
           throw new InvalidDataException();
       }
       byte[] lHash = sha256.digest(label);
       byte[] ps = new byte[k - plainText.length - 2*hLen - 2];
       ByteBuffer buffer = ByteBuffer.allocate(k - hLen - 1);
       buffer.put(lHash);
       buffer.put(ps);
       buffer.put((byte)1);
       buffer.put(plainText);
       byte[] db = buffer.array();
       SecureRandom random = new SecureRandom();
       byte[] seed = new byte[hLen];
       random.nextBytes(seed);
       byte[] dbMask = mgf(seed, k - hLen - 1);
       byte[] maskedDB = new byte[k - hLen - 1];
       for (int i = 0; i < k - hLen - 1; i++) {
           maskedDB[i] = (byte)(db[i] ^ dbMask[i]);
       }
       byte[] seedMask = mgf(maskedDB, hLen);
       byte[] maskedSeed = new byte[hLen];
       for (int i = 0; i < hLen; i++) {
           maskedSeed[i] = (byte)(seed[i] ^ seedMask[i]);
       }
       buffer = ByteBuffer.allocate(k);
       buffer.put((byte)0);
       buffer.put(maskedSeed);
       buffer.put(maskedDB);
       byte[] em = buffer.array();
       byte[] cipherText = encrypt(em, publicKey);
       return cipherText;
   }
   
   public byte[] decryptOAEP(byte[] cipherText, byte[] label, RSA_PrivateKey privateKey) { //RSA-OAEP decryption
       int k; //Length of modulus in bytes
       if (privateKey.getModulus().bitLength() % 8 > 0) {
           k = privateKey.getModulus().bitLength()/8 + 1;
       }
       else {
           k = privateKey.getModulus().bitLength()/8;
       }
       if (cipherText.length < k || cipherText.length > k + 1 || k < 2*hLen + 2) {
           throw new InvalidDataException();
       }
       byte[] em = decrypt(cipherText, privateKey);
       byte[] lHash = sha256.digest(label);
       byte[] maskedSeed = new byte[hLen];
       byte[] maskedDB = new byte[k - hLen - 1];
       if (em[0] == 0) {
           System.arraycopy(em, 1, maskedSeed, 0, hLen);
           System.arraycopy(em, hLen + 1, maskedDB, 0, k - hLen - 1);
       }
       else {
           System.arraycopy(em, 0, maskedSeed, 0, hLen);
           System.arraycopy(em, hLen, maskedDB, 0, k - hLen - 1);
       }
       byte[] seedMask = mgf(maskedDB, hLen);
       byte[] seed = new byte[hLen];
       for (int i = 0; i < hLen; i++) {
           seed[i] = (byte)(maskedSeed[i] ^ seedMask[i]);
       }
       byte[] dbMask = mgf(seed, k - hLen - 1);
       byte[] db = new byte[k - hLen - 1];
       for (int i = 0; i < k - hLen - 1; i++) {
           db[i] = (byte)(maskedDB[i] ^ dbMask[i]);
       }
       byte[] lHashInput = new byte[hLen];
       System.arraycopy(db, 0, lHashInput, 0, hLen);
       if (!Arrays.equals(lHash, lHashInput)) {
           throw new IllegalArgumentException();
       }
       int mIndex = 0;
       switch (db[hLen]) {
           case 1:
               mIndex = hLen + 1;
               break;
           case 0:
               for (int i = hLen; i < k - hLen - 1; i++) {
                   if (db[i] == 1 && db[i-1] == 0) {
                       mIndex = i + 1;
                       break;
                   }
               }
               if (mIndex == 0) {
                    throw new IllegalArgumentException();
               }   
               break;
           default:
               throw new IllegalArgumentException();
       }
       byte[] plainText = new byte[db.length - mIndex];
       System.arraycopy(db, mIndex, plainText, 0, plainText.length);
       return plainText;
   }
}
