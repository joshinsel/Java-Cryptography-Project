package cryptography_project;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import org.bouncycastle.asn1.*;
import java.io.IOException;

/*
Author: Joshua Insel

RSA Public Key in Java
Source: PKCS #1 v2.2
*/

public class RSA_PublicKey {
    private BigInteger n; //RSA modulus
    private BigInteger e; //RSA public exponent
    
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
    
    public byte[] getEncoded() throws IOException { //DER encoding of public key
        ASN1Integer[] integers = {new ASN1Integer(n), new ASN1Integer(e)};
        DERSequence sequence = new DERSequence(integers);
        return sequence.getEncoded();
    }
}
