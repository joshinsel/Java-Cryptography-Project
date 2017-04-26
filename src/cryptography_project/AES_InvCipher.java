package cryptography_project;

import java.io.*;
import java.nio.ByteBuffer;

/*
Author: Joshua Insel

Advanced Encryption Standard (AES) Cipher in Java
Source: FIPS PUB 197
*/
public class AES_InvCipher {
    private AES_Key key; //Key
    private final int nB = 4; //# of 32-bit words in 128-bit block
    private int nK; //# of 32-bit words in key
    private int nR; //# of 32-bit round keys
    private byte[][] roundKeys; //Round keys
    private final byte[] sBox = new byte[256];
    private final byte[] invSBox = new byte[256]; //Inverse substitution box
    private final int[] rCon = {0x01, 0x02, 0x04, 0x08, 0x10, 
        0x20, 0x40, 0x80, 0x1b, 0x36}; //Round constant
    
    public AES_InvCipher() {
        initSBox();
        initInvSBox();
    }
    
    public void setKey(AES_Key inputKey) {
        key = inputKey;
        initN(key.getKeySize());
        keyExpansion();
    }
    
    private void initN(int keySize) { //Initialize key and round key sizes
        switch (keySize) {
            case 128:
                nK = 4;
                nR = 10;
                break;
            case 192:
                nK = 6;
                nR = 12;
                break;
            case 256:
                nK = 8;
                nR = 14;
                break;
            default:
                break;
        }
    }
    
     private void initSBox() { //Initialize substitution box
        try {
            BufferedReader reader = new BufferedReader(new FileReader(new File("sBox.txt")));
            String line;
            for (int i = 0; i < 256; i++) {
                try {
                    line = reader.readLine();
                    sBox[i] = (byte) Integer.parseInt(line, 16);
                } 
                catch (IOException ex) {}
            }
        } 
        catch (FileNotFoundException ex) {}
    }
     
    private void initInvSBox() { //Initialize inverse substitution box
        try {
            BufferedReader reader = new BufferedReader(new FileReader(new File("invSBox.txt")));
            String line;
            for (int i = 0; i < 256; i++) {
                try {
                    line = reader.readLine();
                    invSBox[i] = (byte) Integer.parseInt(line, 16);
                } 
                catch (IOException ex) {}
            }
        } 
        catch (FileNotFoundException ex) {}
    }
    
     private int unsignedInt(int num) { //Converts integers to unsigned representation
        if (num >= 0) {
            return num;
        }
        else {
            return 256 + num;
        }
    }
     
    private byte[] subWord(byte[] word) { 
        byte[] output = new byte[4];
        for (int i = 0; i < 4; i++) {
            output[i] = sBox[unsignedInt((int) (word[i]))];
        }
        return output;
    }
    
    private byte[] rotWord(byte[] word) {
        byte[] output = new byte[4];
        output[0] = word[1];
        output[1] = word[2];
        output[2] = word[3];
        output[3] = word[0];
        return output;
    }
    
    private void keyExpansion() { //Expands key to AES round keys
        byte[] keyData = key.getKey();
        roundKeys = new byte[nB*(nR+1)][4];
        byte[] temp = new byte[4];
        int i;
        
        for (i = 0; i < nK; i++) {
            for (int j = 0; j < 4; j++) {
                roundKeys[i][j] = keyData[4*i+j];
            }
        }
        
        for (i = nK; i < nB*(nR+1); i++) {
            System.arraycopy(roundKeys[i-1], 0, temp, 0, 4);
            if (i % nK == 0) {
                temp = subWord(rotWord(temp));
                temp[0] = (byte) (temp[0] ^ rCon[i/nK-1]);
                for (int j = 1; j < 4; j++) {
                    temp[j] = (byte) (temp[j] ^ 0x00);
                }
            }
            else if ((nK > 6) && (i % nK == 4)) {
                temp = subWord(temp);
            }
            for (int j = 0; j < 4; j++) {
                roundKeys[i][j] = (byte)(roundKeys[i-nK][j] ^ temp[j]);
            }
        }
    }
    
    private byte[][] block2State(byte[] block) { //Converts 128-bit block to state
        byte[][] state = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < nB; j++) {
                state[i][j] = block[i + 4*j];
            }
        }
        return state;
    }
    
    private byte[] state2Block(byte[][] state) { //Converts state to 128-bit block
        byte[] block = new byte[16];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < nB; j++) {
                block[i+4*j] = state[i][j];
            }
        }
        return block;
    }
    
    //AES inverse transformations
    
    private byte[][] addRoundKey(byte[][] state, int round) {
        byte[][] output = new byte[4][4];
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                output[i][j] = (byte) (state[i][j] ^ roundKeys[round*nB+j][i]);
            }
        }
        return output;
    }
    
    
    private byte[][] invSubBytes(byte[][] state) {
        byte[][] output = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i][j] = invSBox[unsignedInt((int) state[i][j])];
            }
        }
        return output;
    }
    
    private byte[][] invShiftRows(byte[][] state) {
        byte[][] output = new byte[4][4];
        System.arraycopy(state[0], 0, output[0], 0, 4);
        for (int i = 1; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i][(j+i)%nB] = state[i][j];
            }
        }
        return output;
    }
    
    private byte gMul(byte a, byte b) { //Galois field multiplication
        byte output = 0;
        byte highBit;
        for (int counter = 0; counter < 8; counter++) {
            if ((b & 0x01) != 0) {
                output ^= a;
            }
            highBit = (byte) (a & 0x80);
            a <<= 1;
            if (highBit != 0) {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        return output;
    }
    
    private byte[][] invMixColumns(byte[][] state) {
        byte[][] output = new byte[4][4];
        for (int j = 0; j < 4; j++) {
            output[0][j] = (byte) (gMul((byte)14, state[0][j]) ^ gMul((byte)11, state[1][j]) ^ gMul((byte)13, state[2][j]) ^ gMul((byte)9, state[3][j]));
            output[1][j] = (byte) (gMul((byte)9, state[0][j]) ^ gMul((byte)14, state[1][j]) ^ gMul((byte)11, state[2][j]) ^ gMul((byte)13, state[3][j]));
            output[2][j] = (byte) (gMul((byte)13, state[0][j]) ^ gMul((byte)9, state[1][j]) ^ gMul((byte)14, state[2][j]) ^ gMul((byte)11, state[3][j]));
            output[3][j] = (byte) (gMul((byte)11, state[0][j]) ^ gMul((byte)13, state[1][j]) ^ gMul((byte)9, state[2][j]) ^ gMul((byte)14, state[3][j]));
        }
        return output;
    }
    
    private byte[] invCipher (byte[] cipherTextBlock) { //AES inverse cipher
        byte[][] state = block2State(cipherTextBlock);
        state = addRoundKey(state, nR);
        for (int round = nR - 1; round > 0; round--) {
            state = invShiftRows(state);
            state = invSubBytes(state);
            state = addRoundKey(state, round);
            state = invMixColumns(state);
        }
        state = invShiftRows(state);
        state = invSubBytes(state);
        state = addRoundKey(state, 0);
        byte[] block = state2Block(state);
        return block;
    }
    
    //Block Cipher Modes of Operation
    //Source: NIST Special Publication 800-38A
    
    public byte[] decryptECB(byte[] cipherText, AES_Key key) { //Electronic Cookbook mode
        setKey(key);
        if (cipherText.length % 16 != 0) {
            throw new InvalidDataException();
        }
        ByteBuffer buffer = ByteBuffer.allocate(cipherText.length);
        byte[] cipherTextBlock = new byte[16];
        for (int i = 0; i < cipherText.length; i += 16) {
            System.arraycopy(cipherText, i, cipherTextBlock, 0, 16);
            buffer.put(invCipher(cipherTextBlock));
        }
        byte[] padded = buffer.array();
        int paddingBytes = (int) padded[padded.length-1];
        for (int i = padded.length - paddingBytes; i < padded.length; i++) {
            if (padded[i] != paddingBytes) {
                throw new InvalidDataException();
            }
        }
        byte[] plainText = new byte[padded.length - paddingBytes];
        System.arraycopy(padded, 0, plainText, 0, plainText.length);
        return plainText;
    }
    
    public byte[] decryptCBC(byte[] cipherText, AES_Key key) { //Cipher Block Chaining mode
        setKey(key);
        if (cipherText.length % 16 != 0) {
            throw new InvalidDataException();
        }
        ByteBuffer buffer = ByteBuffer.allocate(cipherText.length - 16);
        byte[] iv = new byte[16]; //Initialization vector
        byte[] cipherTextBlock = new byte[16];
        byte[] previousCipherTextBlock = new byte[16];
        byte[] xorBlock;
        byte[] plainTextBlock = new byte[16];
        System.arraycopy(cipherText, 0, iv, 0, 16);
        for (int i = 16; i < cipherText.length; i += 16) {
            if (i == 16) {
                System.arraycopy(cipherText, i, cipherTextBlock, 0, 16);
                xorBlock = invCipher(cipherTextBlock);
                for (int j = 0; j < 16; j++) {
                    plainTextBlock[j] = (byte)(xorBlock[j] ^ iv[j]);
                }
            }
            else {
                System.arraycopy(cipherText, i - 16, previousCipherTextBlock, 0, 16);
                System.arraycopy(cipherText, i, cipherTextBlock, 0, 16);
                xorBlock = invCipher(cipherTextBlock);
                for (int j = 0; j < 16; j++) {
                    plainTextBlock[j] = (byte)(xorBlock[j] ^ previousCipherTextBlock[j]);
                }
            }
            buffer.put(plainTextBlock);
        }
        byte[] padded = buffer.array();
        int paddingBytes = (int) padded[padded.length-1];
        for (int i = padded.length - paddingBytes; i < padded.length; i++) {
            if (padded[i] != paddingBytes) {
                throw new InvalidDataException();
            }
        }
        byte[] plainText = new byte[padded.length - paddingBytes];
        System.arraycopy(padded, 0, plainText, 0, plainText.length);
        return plainText;
    }
}
