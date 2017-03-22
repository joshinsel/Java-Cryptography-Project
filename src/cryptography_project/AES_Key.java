package cryptography_project;

import java.security.*;

/*
Author: Joshua Insel

Advanced Encryption Standard (AES) Key Generation and Verification
*/

public class AES_Key {
    private byte[] key; //Key
    
    public AES_Key(){}
    
    public AES_Key(int keySize) {
        generateKey(keySize);
    }
    
    public AES_Key(byte[] inputKey) throws InvalidKeyException {
        setKey(inputKey);
    }
    
    public void generateKey(int keySize) { //Generates AES key (keySize in bits)
        SecureRandom random = new SecureRandom(); //Cryptographically secure pseudo-random number generator
        switch (keySize) {
            case 128:
                key = new byte[16];
                random.nextBytes(key);
                break;
            case 192:
                key = new byte[24];
                random.nextBytes(key);
                break;
            case 256:
                key = new byte[32];
                random.nextBytes(key);
                break;
            default:
                break;
        }
    }
    
    public void setKey(byte[] inputKey) throws InvalidKeyException {
        if (inputKey.length == 16 || inputKey.length == 24 || inputKey.length == 32) {
            key = inputKey;
        }
        else {
            throw new InvalidKeyException();
        }
    }
    
    public byte[] getKey() {
        return key;
    }
    
    public int getKeySize() {
        return key.length * 8;
    }

}
