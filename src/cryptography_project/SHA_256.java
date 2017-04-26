package cryptography_project;

import java.nio.ByteBuffer;
import java.util.Arrays;

/*
Author: Joshua Insel

Secure Hash Algorithm-256 (SHA-256) in Java
Source: FIPS PUB 180-4 (Secure Hash Standard)
*/

public class SHA_256 {
    private byte[] data; //Input data and padded data
    private byte[] padded; //Padded data
    private int blocks; //Number of 512-bit blocks in padded data
    private int m[][]; //Each padded data block represented as 32-bit integers 
    private final int w[] = new int[64]; //Message schedule
    private final int k[] = new int[64]; //32-bit pre-defined constants
    
    //The eight hash values
    private int h0; 
    private int h1;
    private int h2;
    private int h3;
    private int h4;
    private int h5;
    private int h6;
    private int h7;
    
    
    public SHA_256() {  
        initConstants();
    }
    
    private void initConstants() { //Initializes constants
        k[0] = 0x428a2f98;
        k[1] = 0x71374491;
        k[2] = 0xb5c0fbcf;
        k[3] = 0xe9b5dba5;
        k[4] = 0x3956c25b;
        k[5] = 0x59f111f1;
        k[6] = 0x923f82a4;
        k[7] = 0xab1c5ed5;
        k[8] = 0xd807aa98;
        k[9] = 0x12835b01;
        k[10] = 0x243185be;
        k[11] = 0x550c7dc3;
        k[12] = 0x72be5d74;
        k[13] = 0x80deb1fe;
        k[14] = 0x9bdc06a7;
        k[15] = 0xc19bf174;
        k[16] = 0xe49b69c1;
        k[17] = 0xefbe4786;
        k[18] = 0x0fc19dc6;
        k[19] = 0x240ca1cc;
        k[20] = 0x2de92c6f;
        k[21] = 0x4a7484aa;
        k[22] = 0x5cb0a9dc;
        k[23] = 0x76f988da;
        k[24] = 0x983e5152;
        k[25] = 0xa831c66d;
        k[26] = 0xb00327c8;
        k[27] = 0xbf597fc7;
        k[28] = 0xc6e00bf3;
        k[29] = 0xd5a79147;
        k[30] = 0x06ca6351;
        k[31] = 0x14292967;
        k[32] = 0x27b70a85;
        k[33] = 0x2e1b2138;
        k[34] = 0x4d2c6dfc;
        k[35] = 0x53380d13;
        k[36] = 0x650a7354;
        k[37] = 0x766a0abb;
        k[38] = 0x81c2c92e;
        k[39] = 0x92722c85;
        k[40] = 0xa2bfe8a1;
        k[41] = 0xa81a664b;
        k[42] = 0xc24b8b70;
        k[43] = 0xc76c51a3;
        k[44] = 0xd192e819;
        k[45] = 0xd6990624;
        k[46] = 0xf40e3585;
        k[47] = 0x106aa070;
        k[48] = 0x19a4c116;
        k[49] = 0x1e376c08;
        k[50] = 0x2748774c;
        k[51] = 0x34b0bcb5;
        k[52] = 0x391c0cb3;
        k[53] = 0x4ed8aa4a;
        k[54] = 0x5b9cca4f;
        k[55] = 0x682e6ff3;
        k[56] = 0x748f82ee;
        k[57] = 0x78a5636f;
        k[58] = 0x84c87814;
        k[59] = 0x8cc70208;
        k[60] = 0x90befffa;
        k[61] = 0xa4506ceb;
        k[62] = 0xbef9a3f7;
        k[63] = 0xc67178f2;
    }
    
    private void initHashValues() { //Initializes hash values
        h0 = 0x6a09e667;
        h1 = 0xbb67ae85;
        h2 = 0x3c6ef372;
        h3 = 0xa54ff53a;
        h4 = 0x510e527f;
        h5 = 0x9b05688c;
        h6 = 0x1f83d9ab;
        h7 = 0x5be0cd19;
    }
    
    
    private void padding() { //Pads data
        //Pads a single '1' bit and k '0' bits, where 1 + k + length (in bits) ≡ 448 (mod 512)
        if (data.length % 64 < 56) {
            padded = Arrays.copyOf(data, 64*(data.length/64 + 1));
            padded[data.length] = (byte) 0b10000000;
        }
        else {
            padded = Arrays.copyOf(data, 64*(data.length/64 + 2));
            padded[data.length] = (byte) 0b10000000;
        }
        //Pads a 64-bit binary representation of the length of the data in bits
        long data_size = data.length * 8; //Size of data in bits;
        byte[] data_size_bytes = ByteBuffer.allocate(8).putLong(data_size).array(); //data_size as byte array
        System.arraycopy(data_size_bytes, 0, padded, padded.length - 8, data_size_bytes.length);
    }
    
    private void parsing() { //Converts each data block to 32-bit integers
        blocks = padded.length/64;
        m = new int[blocks][16];
        byte[] word = new byte[4]; //32-bit word
        int word_index = 0;
        for (int i = 0; i < blocks; i++) {
            for (int j = 0; j < 16; j++) {
                System.arraycopy(padded, word_index, word, 0, 4);
                m[i][j] = ByteBuffer.wrap(word).getInt();
                word_index += 4;
            }
        }
    }
    
    public byte[] digest(byte[] input) { //Computes message digest
        data = input;
        initHashValues();
        padding();
        parsing();
        
        //The eight working values
        int a;
        int b;
        int c;
        int d;
        int e;
        int f;
        int g;
        int h;
        
        //Temporary variables
        int t1;
        int t2;
        
        for (int i = 0; i < blocks; i++) {
            //Prepares message schedule
            for (int t = 0; t < 64; t++) {
                if (t <= 15) {
                    w[t] = m[i][t];
                }
                else {
                    w[t] = l_sigma1(w[t-2]) + w[t-7] + l_sigma0(w[t-15]) + w[t-16];
                }
            }
            //Initializes working variables
            a = h0;
            b = h1;
            c = h2;
            d = h3;
            e = h4;
            f = h5;
            g = h6;
            h = h7;

            for (int t = 0; t < 64; t++) {
                t1 = h + sigma1(e) + ch(e, f, g) + k[t] + w[t];
                t2 = sigma0(a) + maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }
             
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;
        }
        
        //Prepares message digest as a 256-bit byte array
        ByteBuffer buffer = ByteBuffer.allocate(32);
        buffer.putInt(h0);
        buffer.putInt(h1);
        buffer.putInt(h2);
        buffer.putInt(h3);
        buffer.putInt(h4);
        buffer.putInt(h5);
        buffer.putInt(h6);
        buffer.putInt(h7);
        byte[] digest = buffer.array(); //256-bit message digest
        return digest;
    }
    
    
    private int rotateRight(int x, int n) { //Circular right shift (x: Integer, n: Shift value)
        return (x >>> n) | (x << (32-n));
    }
    
    //SHA-256 Functions
    
    private int ch(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }
    
    private int maj(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    private int sigma0(int x) {
        return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
    }
    
    private int sigma1(int x) {
        return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
    }
    
    private int l_sigma0(int x) {
        return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >>> 3);
    }
    
    private int l_sigma1(int x) {
        return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >>> 10);
    }
    
}
