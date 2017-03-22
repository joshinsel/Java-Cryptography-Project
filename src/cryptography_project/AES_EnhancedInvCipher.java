package cryptography_project;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import org.apache.commons.codec.binary.Hex;

public class AES_EnhancedInvCipher {
    private AES_Key key; //Key
    final private SHA_256 sha256 = new SHA_256();
    final private int nB = 4; //# of 32-bit words in 128-bit block
    final private int nK = 4; //# of 32-bit words in key
    final private int nR = 10; //# of 32-bit round keys
    private byte[][] blockKeys; //Block keys
    private byte[][] roundKeys; //Round keys
    private byte[] sBox = new byte[256]; //Substitution box
    private byte[] invSBox = new byte[256]; //Inverse substitution box
    final private int[] rCon = {0x01, 0x02, 0x04, 0x08, 0x10, 
        0x20, 0x40, 0x80, 0x1b, 0x36}; //Round constant
    
    public AES_EnhancedInvCipher() {
        initSBox();
        initInvSBox();
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
     
    private void initInvSBox() { //Initialize substitution box
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
    
    private void blockKeyGen(int blocks) {
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
            leftHalf = nibbleSwappedRightHalf;
            rightHalf = new byte[8];
            for (int j = 0; j < 8; j++) {
                rightHalf[j] = (byte)(rotatedLeftHalf[j] ^ nibbleSwappedRightHalf[j]);
            }
            byte[] permutedKey = new byte[16];
            System.arraycopy(leftHalf, 0, permutedKey, 0, 8);
            System.arraycopy(rightHalf, 0, permutedKey, 8, 8);
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
    
    private int unsignedInt(int num) {
        if (num >= 0) {
            return num;
        }
        else {
            return 256 + num;
        }
    }
    
    private int signedInt(int num) {
        if (num < 128) {
            return num;
        }
        else {
            return num - 256;
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
    
    private void keyExpansion(byte[] blockKey) {
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
    
    private byte[][] dynamicInvSubBytes(byte[][] state, int round) {
        byte[][] output = new byte[4][4];
        int temp = 0;
        int shift;
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                temp = temp ^ roundKeys[round*nB+j][i];
            }
        }
        shift = unsignedInt((int) temp);
        byte[] rotatedInvSBox = new byte[256];
        //Cyclic left shift of inverse S-Box
        for (int i = 0; i < 256; i++) {
            rotatedInvSBox[unsignedInt(sBox[(i + shift) % 256])] = (byte)(signedInt(i));
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i][j] = rotatedInvSBox[unsignedInt((int) state[i][j])];
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
    
    private byte[] invCipher (byte[] cipherTextBlock) {
        byte[][] state = block2State(cipherTextBlock);
        state = addRoundKey(state, nR);
        state = invShiftRows(state);
        state = dynamicInvSubBytes(state, nR);
        for (int round = nR - 1; round > 0; round--) {
            state = addRoundKey(state, round);
            state = invMixColumns(state);
            state = invShiftRows(state);
            state = dynamicInvSubBytes(state, round);
        }
        state = addRoundKey(state, 0);
        byte[] block = state2Block(state);
        return block;
    }
    
    public byte[] decryptECB(byte[] cipherText, AES_Key key) {
        setKey(key, cipherText.length/16 - 1);
        if (cipherText.length % 16 != 0) {
            throw new InvalidDataException();
        }
        ByteBuffer buffer = ByteBuffer.allocate(cipherText.length);
        byte[] block = new byte[16];
        for (int i = 0; i < cipherText.length; i += 16) {
            keyExpansion(blockKeys[i/16 - 1]);
            System.arraycopy(cipherText, i, block, 0, 16);
            buffer.put(invCipher(block));
        }
        byte[] padded = buffer.array();
        int paddingBytes = (int) padded[padded.length-1];
        for (int i = padded.length - paddingBytes; i < padded.length; i++) {
            if (padded[i] != paddingBytes) {
                throw new InvalidDataException();
            }
        }
        byte[] data = new byte[padded.length - paddingBytes];
        System.arraycopy(padded, 0, data, 0, data.length);
        return data;
    }
    
    public byte[] decryptCBC(byte[] cipherText, AES_Key key) {
        setKey(key, cipherText.length/16 - 1);
        if (cipherText.length % 16 != 0) {
            throw new InvalidDataException();
        }
        ByteBuffer buffer = ByteBuffer.allocate(cipherText.length - 16);
        byte[] iv = new byte[16];
        byte[] block = new byte[16];
        byte[] previousBlock = new byte[16];
        System.arraycopy(cipherText, 0, iv, 0, 16);
        for (int i = 16; i < cipherText.length; i += 16) {
            keyExpansion(blockKeys[i/16 - 1]);
            if (i == 16) {
                System.arraycopy(cipherText, i, block, 0, 16);
                block = invCipher(block);
                for (int j = 0; j < 16; j++) {
                    block[j] = (byte)(block[j] ^ iv[j]);
                }
            }
            else {
                System.arraycopy(cipherText, i - 16, previousBlock, 0, 16);
                System.arraycopy(cipherText, i, block, 0, 16);
                block = invCipher(block);
                for (int j = 0; j < 16; j++) {
                    block[j] = (byte)(block[j] ^ previousBlock[j]);
                }
            }
            buffer.put(block);
        }
        byte[] padded = buffer.array();
        int paddingBytes = (int) padded[padded.length-1];
        if (paddingBytes < 0 || paddingBytes > 16) {
            throw new InvalidDataException();
        }
        else {
            for (int i = padded.length - paddingBytes; i < padded.length; i++) {
                if (padded[i] != paddingBytes) {
                    throw new InvalidDataException();
                }
            }
            byte[] data = new byte[padded.length - paddingBytes];
            System.arraycopy(padded, 0, data, 0, data.length);
            return data;
        }
    }
}
