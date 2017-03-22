package cryptography_project;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

/*
Author: Joshua Insel

Advanced Encryption Standard (AES) Cipher in Java
Source: FIPS PUB 197
*/

public class AES_Cipher {
    private AES_Key key; //Key
    final private int nB = 4; //# of 32-bit words in 128-bit block
    private int nK; //# of 32-bit words in key
    private int nR; //# of 32-bit round keys
    private byte[][] roundKeys; //Round keys
    private byte[] sBox = new byte[256]; //Substitution box
    final private int[] rCon = {0x01, 0x02, 0x04, 0x08, 0x10, 
        0x20, 0x40, 0x80, 0x1b, 0x36}; //Round constant
    
    public AES_Cipher(){
        initSBox();
    }
    
    public void setKey(AES_Key inputKey) {
        key = inputKey;
        initN(key.getKeySize());
        keyExpansion();
    }
    
    private void initN(int keySize) { //Initialize key and round key numbers
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
    
    
    private int unsignedInt(int num) {
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
    
    private void keyExpansion() {
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
    
    private byte[][] block2State(byte[] block) {
        byte[][] state = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < nB; j++) {
                state[i][j] = block[i + 4*j];
            }
        }
        return state;
    }
    
    private byte[] state2Block(byte[][] state) {
        byte[] block = new byte[16];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < nB; j++) {
                block[i+4*j] = state[i][j];
            }
        }
        return block;
    }
    
    private byte[][] addRoundKey(byte[][] state, int round) {
        byte[][] output = new byte[4][4];
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                output[i][j] = (byte) (state[i][j] ^ roundKeys[round*nB+j][i]);
            }
        }
        return output;
    }
    
    private byte[][] subBytes(byte[][] state) {
        byte[][] output = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i][j] = sBox[unsignedInt((int) state[i][j])];
            }
        }
        return output;
    }
    
    private byte[][] shiftRows(byte[][] state) {
        byte[][] output = new byte[4][4];
        System.arraycopy(state[0], 0, output[0], 0, 4);
        for (int i = 1; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i][j] = state[i][(j+i)%nB];
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
    
    private byte[][] mixColumns(byte[][] state) {
        byte[][] output = new byte[4][4];
        for (int j = 0; j < 4; j++) {
            output[0][j] = (byte) (gMul((byte)2, state[0][j]) ^ gMul((byte)3, state[1][j]) ^ state[2][j] ^ state[3][j]);
            output[1][j] = (byte) (state[0][j] ^ gMul((byte)2, state[1][j]) ^ gMul((byte)3, state[2][j]) ^ state[3][j]);
            output[2][j] = (byte) (state[0][j] ^ state[1][j] ^ gMul((byte)2, state[2][j]) ^ gMul((byte)3, state[3][j]));
            output[3][j] = (byte) (gMul((byte)3, state[0][j]) ^ state[1][j] ^ state[2][j] ^ gMul((byte)2, state[3][j]));
        }
        return output;
    }
    

    
    public byte[] cipher(byte[] inputBlock) {
        byte[][] state = block2State(inputBlock);
        state = addRoundKey(state, 0);
        for (int round = 1; round < nR; round++) {
            state = subBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            state = addRoundKey(state, round);
        }
        state = subBytes(state);
        state = shiftRows(state);
        state = addRoundKey(state, nR);
        byte[] cipherTextBlock = state2Block(state);
        return cipherTextBlock;
    }
    
    private byte[] padding(byte[] data) { //PKCS #7 Padding
        ByteBuffer buffer;
        int paddedLength;
        if (data.length % 16 > 0) {
            paddedLength = 16*(data.length/16 + 1);
            buffer = ByteBuffer.allocate(paddedLength);
            buffer.put(data);
            for (int i = 0; i < paddedLength - data.length; i++) {
                buffer.put((byte)(paddedLength - data.length));
            }
        }
        else {
            paddedLength = 16*(data.length/16 + 2);
            buffer = ByteBuffer.allocate(paddedLength);
            buffer.put(data);
            for (int i = 0; i < paddedLength - data.length; i++) {
                buffer.put((byte)(paddedLength - data.length));
            }
        }
        return buffer.array();
    }
    
    public byte[] encryptECB(byte[] data) { //Electronic Cookbook mode
        data = padding(data);
        ByteBuffer buffer = ByteBuffer.allocate(data.length);
        byte[] block = new byte[16];
        for (int i = 0; i < data.length; i += 16) {
            System.arraycopy(data, i, block, 0, 16);
            buffer.put(cipher(block));
        }
        byte[] cipherText = buffer.array();
        return cipherText;
    }
    
    public byte[] encryptCBC(byte[] data) { //Cipher Block Chaining mode
        data = padding(data);
        SecureRandom random = new SecureRandom(); //Cryptographically-secure pseudorandom number generator
        ByteBuffer buffer = ByteBuffer.allocate(data.length + 16);
        byte[] iv = new byte[16]; //Initialization vector
        random.nextBytes(iv);
        buffer.put(iv);
        byte[] dataBlock = new byte[16];
        byte[] cipherTextBlock = new byte[16];
        for (int i = 0; i < data.length; i += 16) {
            System.arraycopy(data, i, dataBlock, 0, 16);
            if (i == 0) {
                for (int j = 0; j < 16; j++) {
                    cipherTextBlock[j] = (byte)(dataBlock[j] ^ iv[j]);
                }
                cipherTextBlock = cipher(cipherTextBlock);
                buffer.put(cipherTextBlock);
            }
            else {
                for (int j = 0; j < 16; j++) {
                    cipherTextBlock[j] = (byte)(dataBlock[j] ^ cipherTextBlock[j]);
                }
                cipherTextBlock = cipher(cipherTextBlock);
                buffer.put(cipherTextBlock);
            }
        }
        byte[] cipherText = buffer.array();
        return cipherText;
    }
}
