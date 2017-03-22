package cryptography_project;

import java.math.BigInteger;
import java.security.InvalidKeyException;

public class RSA_PublicKey {
    private BigInteger n; //RSA Modulus
    private BigInteger e; //RSA Public Exponent
    
    public RSA_PublicKey(BigInteger modulus, BigInteger exponent) throws InvalidKeyException {
        if (exponent.compareTo(BigInteger.valueOf(3)) == -1 || exponent.compareTo(modulus) >= 0) {
            throw new InvalidKeyException();
        }
        n = modulus;
        e = exponent;
    }
    
    public BigInteger getModulus() {
        return n;
    }
    
    public BigInteger getPublicExponent() {
        return e;
    }
}
