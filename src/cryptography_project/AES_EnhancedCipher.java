package cryptography_project;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

/*
Author: Joshua Insel

Enhanced Advanced Encryption Standard (AES) Cipher in Java
Source: "Enhancing AES using Novel Block Key Generation Algorithm and Key Dependent S-boxes" by Harpreet Singh and Paramvir Singh
*/

public class AES_EnhancedCipher {
    private AES_Key key; //Key
    final private SHA_256 sha256 = new SHA_256(); //Secure Hash Algorithm-256
    final private int nB = 4; //# of 32-bit words in 128-bit block
    final private int nK = 4; //# of 32-bit words in key
    final private int nR = 10; //# of 32-bit round keys
    private byte[][] blockKeys; //Block keys
    private byte[][] roundKeys; //Round keys
    private final byte[] sBox = new byte[256]; //Substitution box
    final private int[] rCon = {0x01, 0x02, 0x04, 0x08, 0x10, 
        0x20, 0x40, 0x80, 0x1b, 0x36}; //Round constant
    
    public AES_EnhancedCipher() {
        initSBox();
    }
    
    private void setKey(AES_Key inputKey, int blocks) {
        key = inputKey;
        blockKeyGen(blocks);
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
    
    
    private void blockKeyGen(int blocks) { //Block key generation algorithm
        blockKeys = new byte[blocks][16];
        byte[] keyData = key.getKey();
        byte[] blockKey = new byte[16];
        for (int i = 0; i < blocks; i++) {
            //Permutation function
            byte[] leftHalf = new byte[8];
            byte[] rightHalf = new byte[8];
            if (i == 0) {
                System.arraycopy(keyData, 0, leftHalf, 0, 8);
                System.arraycopy(keyData, 8, rightHalf, 0, 8);
            }
            else {
                System.arraycopy(blockKey, 0, leftHalf, 0, 8);
                System.arraycopy(blockKey, 8, rightHalf, 0, 8);
            }
            //Cyclic left rotation of left half and Nibble swap of right half
            byte[] rotatedLeftHalf = new byte[8];
            byte[] nibbleSwappedRightHalf = new byte[8];
            for (int j = 0; j < 8; j++) {
                rotatedLeftHalf[j] = leftHalf[(j + 4) % 4];
                nibbleSwappedRightHalf[j] = (byte)(((rightHalf[j] & 0x0f) << 4) | ((rightHalf[j] & 0xf0) >>> 4));
            }
            byte[] permutedLeftHalf = nibbleSwappedRightHalf;
            byte[] permutedRightHalf = new byte[8];
            for (int j = 0; j < 8; j++) {
                permutedRightHalf[j] = (byte)(rotatedLeftHalf[j] ^ nibbleSwappedRightHalf[j]);
            }
            byte[] permutedKey = new byte[16];
            System.arraycopy(permutedLeftHalf, 0, permutedKey, 0, 8);
            System.arraycopy(permutedRightHalf, 0, permutedKey, 8, 8);
            //XOR of original key and output of permutation function
            byte[] xorKey = new byte[16];
            for (int j = 0; j < 16; j++) {
                xorKey[j] = (byte)(permutedKey[j] ^ keyData[j]);
            }
            //SHA-256 message digest of XOR'ed key
            byte[] keyDigest = sha256.digest(xorKey);
            byte[] digestLeftHalf = new byte[16];
            byte[] digestRightHalf = new byte[16];
            System.arraycopy(keyDigest, 0, digestLeftHalf, 0, 16);
            System.arraycopy(keyDigest, 16, digestRightHalf, 0, 16);
            for (int j = 0; j < 16; j++) {
                blockKey[j] = (byte)(digestLeftHalf[j] ^ digestRightHalf[j]);
            }
            System.arraycopy(blockKey, 0, blockKeys[i], 0, 16);
        }
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
    
    private void keyExpansion(byte[] blockKey) { //Expands key to AES round keys
        roundKeys = new byte[nB*(nR+1)][4];
        byte[] temp = new byte[4];
        int i;
        for (i = 0; i < nK; i++) {
            for (int j = 0; j < 4; j++) {
                roundKeys[i][j] = blockKey[4*i+j];
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
    
    //Enhanced AES transformations
    
    private byte[][] addRoundKey(byte[][] state, int round) {
        byte[][] output = new byte[4][4];
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                output[i][j] = (byte) (state[i][j] ^ roundKeys[round*nB+j][i]);
            }
        }
        return output;
    }
    
    private byte[][] dynamicSubBytes(byte[][] state, int round) {
        byte[][] output = new byte[4][4];
        int temp = 0;
        int shift;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                temp = temp ^ roundKeys[round*nB+j][i];
            }
        }
        shift = unsignedInt((int) temp);
        byte[] rotatedSBox = new byte[256];
        //Cyclic left shift of S-Box
        for (int i = 0; i < 256; i++) {
            rotatedSBox[i] = sBox[(i + shift) % 256];
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i][j] = rotatedSBox[unsignedInt((int) state[i][j])];
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
    

    
    private byte[] cipher(byte[] inputBlock) { //Enhanced AES cipher
        byte[][] state = block2State(inputBlock);
        state = addRoundKey(state, 0);
        for (int round = 1; round < nR; round++) {
            state = dynamicSubBytes(state, round);
            state = shiftRows(state);
            state = mixColumns(state);
            state = addRoundKey(state, round);
        }
        state = dynamicSubBytes(state, nR);
        state = shiftRows(state);
        state = addRoundKey(state, nR);
        byte[] cipherTextBlock = state2Block(state);
        return cipherTextBlock;
    }
    
    private byte[] padding(byte[] plainText) { //PKCS #7 Padding
        ByteBuffer buffer;
        int paddedLength;
        if (plainText.length % 16 > 0) {
            paddedLength = 16*(plainText.length/16 + 1);
            buffer = ByteBuffer.allocate(paddedLength);
            buffer.put(plainText);
            for (int i = 0; i < paddedLength - plainText.length; i++) {
                buffer.put((byte)(paddedLength - plainText.length));
            }
        }
        else {
            paddedLength = 16*(plainText.length/16 + 2);
            buffer = ByteBuffer.allocate(paddedLength);
            buffer.put(plainText);
            for (int i = 0; i < paddedLength - plainText.length; i++) {
                buffer.put((byte)(paddedLength - plainText.length));
            }
        }
        return buffer.array();
    }
    
    //Block Cipher Modes of Operation
    //Source: NIST Special Publication 800-38A
    
    public byte[] encryptECB(byte[] plainText, AES_Key key) { //Electronic Cookbook mode
        plainText = padding(plainText);
        setKey(key, plainText.length/16);
        ByteBuffer buffer = ByteBuffer.allocate(plainText.length);
        byte[] plainTextBlock = new byte[16];
        for (int i = 0; i < plainText.length; i += 16) {
            keyExpansion(blockKeys[i/16]);
            System.arraycopy(plainText, i, plainTextBlock, 0, 16);
            buffer.put(cipher(plainTextBlock));
        }
        byte[] cipherText = buffer.array();
        return cipherText;
    }
    
    public byte[] encryptCBC(byte[] plainText, AES_Key key) { //Cipher Block Chaining mode
        plainText = padding(plainText);
        setKey(key, plainText.length/16);
        SecureRandom random = new SecureRandom(); //Cryptographically-secure pseudorandom number generator
        ByteBuffer buffer = ByteBuffer.allocate(plainText.length + 16);
        byte[] iv = new byte[16]; //Initialization vector
        random.nextBytes(iv);
        buffer.put(iv);
        byte[] plainTextBlock = new byte[16];
        byte[] xorBlock = new byte[16];
        byte[] cipherTextBlock = new byte[16];
        for (int i = 0; i < plainText.length; i += 16) {
            keyExpansion(blockKeys[i/16]);
            System.arraycopy(plainText, i, plainTextBlock, 0, 16);
            if (i == 0) {
                for (int j = 0; j < 16; j++) {
                    xorBlock[j] = (byte)(plainTextBlock[j] ^ iv[j]);
                }
                cipherTextBlock = cipher(xorBlock);
                buffer.put(cipherTextBlock);
            }
            else {
                for (int j = 0; j < 16; j++) {
                    xorBlock[j] = (byte)(plainTextBlock[j] ^ cipherTextBlock[j]);
                }
                cipherTextBlock = cipher(xorBlock);
                buffer.put(cipherTextBlock);
            }
        }
        byte[] cipherText = buffer.array();
        return cipherText;
    }
    
    public byte[] encryptCFB(byte[] plainText, AES_Key key) { //Cipher Feedback mode
        setKey(key, plainText.length/16 + 1);
        SecureRandom random = new SecureRandom(); //Cryptographically-secure pseudorandom number generator
        ByteBuffer buffer = ByteBuffer.allocate(plainText.length + 16);
        byte[] iv = new byte[16]; //Initialization vector
        random.nextBytes(iv);
        buffer.put(iv);
        byte[] output;
        byte[] plainTextBlock = new byte[16];
        byte[] cipherTextBlock = new byte[16];
        for (int i = 0; i < plainText.length; i += 16) {
            keyExpansion(blockKeys[i/16]);
            if (i == 0) {
                output = cipher(iv);
            }
            else {
                output = cipher(cipherTextBlock);
            }
            if (plainText.length - i < 16) {
                int blockLength = plainText.length % 16;
                plainTextBlock = new byte[blockLength];
                cipherTextBlock = new byte[blockLength];
                System.arraycopy(plainText, i, plainTextBlock, 0, blockLength);
                for (int j = 0; j < blockLength; j++) {
                    cipherTextBlock[j] = (byte)(plainTextBlock[j] ^ output[j]);
                }
                buffer.put(cipherTextBlock);
            }
            else {
                System.arraycopy(plainText, i, plainTextBlock, 0, 16);
                for (int j = 0; j < 16; j++) {
                    cipherTextBlock[j] = (byte)(plainTextBlock[j] ^ output[j]);
                }
                buffer.put(cipherTextBlock);
            }
        }
        byte[] cipherText = buffer.array();
        return cipherText;
    }
    
    public byte[] decryptCFB(byte[] cipherText, AES_Key key) {
        setKey(key, cipherText.length/16);
        ByteBuffer buffer = ByteBuffer.allocate(cipherText.length - 16);
        byte[] iv = new byte[16]; //Initialization vector
        byte[] output;
        byte[] cipherTextBlock = new byte[16];
        byte[] plainTextBlock = new byte[16];
        System.arraycopy(cipherText, 0, iv, 0, 16);
        for (int i = 16; i < cipherText.length; i += 16) {
            keyExpansion(blockKeys[i/16 - 1]);
            if (i == 16) {
                output = cipher(iv);
            }
            else {
                output = cipher(cipherTextBlock);
            }
            if (cipherText.length - i < 16) {
                int blockLength = cipherText.length % 16;
                cipherTextBlock = new byte[blockLength];
                plainTextBlock = new byte[blockLength];
                System.arraycopy(cipherText, i, cipherTextBlock, 0, blockLength);
                for (int j = 0; j < blockLength; j++) {
                    plainTextBlock[j] = (byte)(cipherTextBlock[j] ^ output[j]);
                }
                buffer.put(plainTextBlock);
            }
            else {
                System.arraycopy(cipherText, i, cipherTextBlock, 0, 16);
                for (int j = 0; j < 16; j++) {
                    plainTextBlock[j] = (byte)(cipherTextBlock[j] ^ output[j]);
                }
                buffer.put(plainTextBlock);
            }
        }
        byte[] plainText = buffer.array();
        return plainText;
    }
    
    public byte[] encryptOFB(byte[] plainText, AES_Key key) { //Output Feedback mode
        setKey(key, plainText.length/16 + 1);
        SecureRandom random = new SecureRandom(); //Cryptographically-secure pseudorandom number generator
        ByteBuffer buffer = ByteBuffer.allocate(plainText.length + 16);
        byte[] iv = new byte[16]; //Initialization vector
        random.nextBytes(iv);
        buffer.put(iv);
        byte[] output = null;
        byte[] cipherTextBlock = new byte[16];
        byte[] plainTextBlock = new byte[16];
        for (int i = 0; i < plainText.length; i += 16) {
            keyExpansion(blockKeys[i/16]);
            if (i == 0) {
                output = cipher(iv);
            }
            else {
                output = cipher(output);
            }
            if (plainText.length - i < 16) {
                int blockLength = plainText.length % 16;
                plainTextBlock = new byte[blockLength];
                cipherTextBlock = new byte[blockLength];
                System.arraycopy(plainText, i, plainTextBlock, 0, blockLength);
                for (int j = 0; j < blockLength; j++) {
                    cipherTextBlock[j] = (byte)(plainTextBlock[j] ^ output[j]);
                }
                buffer.put(cipherTextBlock);
            }
            else {
                System.arraycopy(plainText, i, plainTextBlock, 0, 16);
                for (int j = 0; j < 16; j++) {
                    cipherTextBlock[j] = (byte)(plainTextBlock[j] ^ output[j]);
                }
                buffer.put(cipherTextBlock);
            }
        }
        byte[] cipherText = buffer.array();
        return cipherText;
    }
    
    public byte[] decryptOFB(byte[] cipherText, AES_Key key) {
        setKey(key, cipherText.length/16);
        ByteBuffer buffer = ByteBuffer.allocate(cipherText.length - 16);
        byte[] iv = new byte[16]; //Initialization vector
        byte[] output = null;
        byte[] cipherTextBlock = new byte[16];
        byte[] plainTextBlock = new byte[16];
        System.arraycopy(cipherText, 0, iv, 0, 16);
        for (int i = 16; i < cipherText.length; i += 16) {
            keyExpansion(blockKeys[i/16 - 1]);
            if (i == 16) {
                output = cipher(iv);
            }
            else {
                output = cipher(output);
            }
            if (cipherText.length - i < 16) {
                int blockLength = cipherText.length % 16;
                cipherTextBlock = new byte[blockLength];
                plainTextBlock = new byte[blockLength];
                System.arraycopy(cipherText, i, cipherTextBlock, 0, blockLength);
                for (int j = 0; j < blockLength; j++) {
                    plainTextBlock[j] = (byte)(cipherTextBlock[j] ^ output[j]);
                }
                buffer.put(plainTextBlock);
            }
            else {
                System.arraycopy(cipherText, i, cipherTextBlock, 0, 16);
                for (int j = 0; j < 16; j++) {
                    plainTextBlock[j] = (byte)(cipherTextBlock[j] ^ output[j]);
                }
                buffer.put(plainTextBlock);
            }
        }
        byte[] plainText = buffer.array();
        return plainText;
    }
}
