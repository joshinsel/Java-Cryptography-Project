/*
Joshua Insel
*/

package cryptography_project;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.*;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.DecoderException;
import org.bouncycastle.asn1.*;
/**
 *
 * @author joshi
 */
public class Cryptography_Project {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, DecoderException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        String testString = "This string is being used to test RSA.";
        byte[] testBytes = testString.getBytes();
        RSA_KeyGenerator keygen = new RSA_KeyGenerator();
        keygen.generateKeys(1024);
        RSA_PublicKey publicKey = keygen.getPublicKey();
        RSA_PrivateKey privateKey = keygen.getPrivateKey();
        RSA_Cipher cipher = new RSA_Cipher();
        byte[] ctext = cipher.encryptOAEP(testBytes, "".getBytes(), publicKey);
        testBytes = cipher.decryptOAEP(ctext, "".getBytes(), privateKey);
        testString = new String(testBytes);
        System.out.println(testString);
    }
}
