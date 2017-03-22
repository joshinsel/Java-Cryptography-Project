package cryptography_project;

//Author: Joshua Insel

//RSA Key Generator
//Generates public and private keys for RSA

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RSA_KeyGenerator {
    
    private SecureRandom random = new SecureRandom(); //Cryptographically-secure random number generator
    private BigInteger p; //First random prime number
    private BigInteger q; //Second random prime number
    private BigInteger lcm; //Least common multiple of (p-1) and (q-1)
    private BigInteger n; //RSA modulus
    private BigInteger e; //RSA public exponent
    private BigInteger d; //RSA private exponent
    private RSA_PublicKey publicKey; 
    private RSA_PrivateKey privateKey;
    
    public RSA_KeyGenerator() {}
    
    public void generateKeys(int keyLength) { //Input: Length of key in bits
        random.setSeed(random.generateSeed(keyLength/8));
        p = new BigInteger(keyLength/2, 100, random);
        q = new BigInteger(keyLength/2, 100, random);
        n = p.multiply(q);
        lcm = getLCM(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE)); 
        e = BigInteger.valueOf(65537); //The Fermat prime 65537
        d = e.modInverse(lcm);
        try {
            publicKey = new RSA_PublicKey(n, e);
        } 
        catch (InvalidKeyException ex) {}
        try {
            privateKey = new RSA_PrivateKey(n, d);
        } 
        catch (InvalidKeyException ex) {}
    }
    
    private BigInteger getLCM(BigInteger x, BigInteger y) { //Least common multiple
        return x.multiply(y).divide(x.gcd(y));
    }
    
    public RSA_PublicKey getPublicKey() {
        return publicKey;
    }
    
    public RSA_PrivateKey getPrivateKey() {
        return privateKey;
    }
}
