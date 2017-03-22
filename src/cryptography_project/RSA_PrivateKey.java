package cryptography_project;

import java.math.BigInteger;
import java.security.InvalidKeyException;

public class RSA_PrivateKey {
    BigInteger n; //RSA Modulus
    BigInteger d; //RSA Private Exponent
    
    public RSA_PrivateKey(BigInteger modulus, BigInteger exponent) throws InvalidKeyException {
        if (exponent.compareTo(modulus) >= 0) {
            throw new InvalidKeyException();
        }
        n = modulus;
        d = exponent;
    }
    
    public BigInteger getModulus() {
        return n;
    }
    
    public BigInteger getPrivateExponent() {
        return d;
    }
}
