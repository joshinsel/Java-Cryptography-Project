package cryptography_project;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import org.bouncycastle.asn1.*;
import java.io.IOException;

/*
Author: Joshua Insel

RSA Private Key in Java
Source: PKCS #1 v2.2
*/

public class RSA_PrivateKey {
    private BigInteger n; //RSA modulus
    private BigInteger d; //RSA private exponent
    
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
    
    public byte[] getEncoded() throws IOException { //DER encoding of private key
        ASN1Integer[] integers = {new ASN1Integer(n), new ASN1Integer(d)};
        DERSequence sequence = new DERSequence(integers);
        return sequence.getEncoded();
    }
}
