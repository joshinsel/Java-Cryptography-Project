package cryptography_project;

/*
Author: Joshua Insel

Secure Hash Algorithm-512 (SHA-512) in Java
Source: FIPS PUB 180-4 (Secure Hash Standard)
*/

import java.nio.ByteBuffer;
import java.util.ArrayList;

public class SHA_512 {
    
    private ArrayList<byte[]> data; //Input data and padded data
    private int blocks; //Number of 1024-bit blocks in padded data
    private long m[][]; //Each padded data block represented as 64-bit integers
    private long w[] = new long[80]; //Message schedule
    private long k[] = new long[80]; //64-bit pre-defined constants
   
    //The eight hash values
    long h0;
    long h1;
    long h2;
    long h3;
    long h4;
    long h5;
    long h6;
    long h7;
    
    public SHA_512() {
        data = new ArrayList<>();
        initConstants();
    }
    
    private void initConstants() {
        k[0] = 0x428a2f98d728ae22L;
        k[1] = 0x7137449123ef65cdL;
        k[2] = 0xb5c0fbcfec4d3b2fL;
        k[3] = 0xe9b5dba58189dbbcL;
        k[4] = 0x3956c25bf348b538L;
        k[5] = 0x59f111f1b605d019L;
        k[6] = 0x923f82a4af194f9bL;
        k[7] = 0xab1c5ed5da6d8118L;
        k[8] = 0xd807aa98a3030242L;
        k[9] = 0x12835b0145706fbeL;
        k[10] = 0x243185be4ee4b28cL;
        k[11] = 0x550c7dc3d5ffb4e2L;
        k[12] = 0x72be5d74f27b896fL;
        k[13] = 0x80deb1fe3b1696b1L;
        k[14] = 0x9bdc06a725c71235L;
        k[15] = 0xc19bf174cf692694L;
        k[16] = 0xe49b69c19ef14ad2L;
        k[17] = 0xefbe4786384f25e3L;
        k[18] = 0x0fc19dc68b8cd5b5L;
        k[19] = 0x240ca1cc77ac9c65L;
        k[20] = 0x2de92c6f592b0275L;
        k[21] = 0x4a7484aa6ea6e483L;
        k[22] = 0x5cb0a9dcbd41fbd4L;
        k[23] = 0x76f988da831153b5L;
        k[24] = 0x983e5152ee66dfabL;
        k[25] = 0xa831c66d2db43210L;
        k[26] = 0xb00327c898fb213fL;
        k[27] = 0xbf597fc7beef0ee4L;
        k[28] = 0xc6e00bf33da88fc2L;
        k[29] = 0xd5a79147930aa725L;
        k[30] = 0x06ca6351e003826fL;
        k[31] = 0x142929670a0e6e70L;
        k[32] = 0x27b70a8546d22ffcL;
        k[33] = 0x2e1b21385c26c926L;
        k[34] = 0x4d2c6dfc5ac42aedL;
        k[35] = 0x53380d139d95b3dfL;
        k[36] = 0x650a73548baf63deL;
        k[37] = 0x766a0abb3c77b2a8L;
        k[38] = 0x81c2c92e47edaee6L;
        k[39] = 0x92722c851482353bL;
        k[40] = 0xa2bfe8a14cf10364L;
        k[41] = 0xa81a664bbc423001L;
        k[42] = 0xc24b8b70d0f89791L;
        k[43] = 0xc76c51a30654be30L;
        k[44] = 0xd192e819d6ef5218L;
        k[45] = 0xd69906245565a910L;
        k[46] = 0xf40e35855771202aL;
        k[47] = 0x106aa07032bbd1b8L;
        k[48] = 0x19a4c116b8d2d0c8L;
        k[49] = 0x1e376c085141ab53L;
        k[50] = 0x2748774cdf8eeb99L;
        k[51] = 0x34b0bcb5e19b48a8L;
        k[52] = 0x391c0cb3c5c95a63L;
        k[53] = 0x4ed8aa4ae3418acbL;
        k[54] = 0x5b9cca4f7763e373L;
        k[55] = 0x682e6ff3d6b2b8a3L;
        k[56] = 0x748f82ee5defb2fcL;
        k[57] = 0x78a5636f43172f60L;
        k[58] = 0x84c87814a1f0ab72L;
        k[59] = 0x8cc702081a6439ecL;
        k[60] = 0x90befffa23631e28L;
        k[61] = 0xa4506cebde82bde9L;
        k[62] = 0xbef9a3f7b2c67915L;
        k[63] = 0xc67178f2e372532bL;
        k[64] = 0xca273eceea26619cL;
        k[65] = 0xd186b8c721c0c207L;
        k[66] = 0xeada7dd6cde0eb1eL;
        k[67] = 0xf57d4f7fee6ed178L;
        k[68] = 0x06f067aa72176fbaL;
        k[69] = 0x0a637dc5a2c898a6L;
        k[70] = 0x113f9804bef90daeL;
        k[71] = 0x1b710b35131c471bL;
        k[72] = 0x28db77f523047d84L;
        k[73] = 0x32caab7b40c72493L;
        k[74] = 0x3c9ebe0a15c9bebcL;
        k[75] = 0x431d67c49c100d4cL;
        k[76] = 0x4cc5d4becb3e42b6L;
        k[77] = 0x597f299cfc657e2aL;
        k[78] = 0x5fcb6fab3ad6faecL;
        k[79] = 0x6c44198c4a475817L;
    }
    
    private void initHashValues() {
        h0 = 0x6a09e667f3bcc908L;
        h1 = 0xbb67ae8584caa73bL;
        h2 = 0x3c6ef372fe94f82bL;
        h3 = 0xa54ff53a5f1d36f1L;
        h4 = 0x510e527fade682d1L;
        h5 = 0x9b05688c2b3e6c1fL;
        h6 = 0x1f83d9abfb41bd6bL;
        h7 = 0x5be0cd19137e2179L;
    }
    
    public void update(byte[] input) { //Adds input data to data array list
        data.add(input);
    }
    
    private void padding() { //Pads data
        byte[] dataEnd = data.get(data.size()-1); //Last byte array in data array list
        byte[] padded; //Padded data
        //Pads a single '1' bit and k '0' bits, where 1 + k + length (in bits) ≡ 896 (mod 512)
        if (dataEnd.length % 128 < 112) {
            padded = new byte[128*(dataEnd.length/128 + 1)];
            System.arraycopy(dataEnd, 0, padded, 0, dataEnd.length);
            padded[dataEnd.length] = (byte) 0b10000000;
        }
        else {
            padded = new byte[128*(dataEnd.length/128 + 2)];
            System.arraycopy(dataEnd, 0, padded, 0, dataEnd.length);
            padded[dataEnd.length] = (byte) 0b10000000;
        }
        //Pads a 128-bit binary representation of the length of the data in bits
        long data_size = (dataEnd.length + ((data.size() - 1) * Integer.MAX_VALUE)) * 8; //Size of data in bits
        byte[] data_size_bytes = ByteBuffer.allocate(8).putLong(data_size).array(); //data_size as byte array
        System.arraycopy(data_size_bytes, 0, padded, padded.length - 8, data_size_bytes.length);
        data.set(data.size() - 1, padded);
    }
    
    private void parsing(int data_index) { //Converts each data block to 64-bit integers
        blocks = data.get(data_index).length/128;
        m = new long[blocks][16];
        int index = 0;
        byte[] word = new byte[8]; //64-bit word
        for (int i = 0; i < blocks; i++) {
            for (int j = 0; j < 16; j++) {
                System.arraycopy(data.get(data_index), index, word, 0, 8);
                m[i][j] = ByteBuffer.wrap(word).getLong();
                index += 8;
            }
        }
    }
    
    public byte[] digest(byte[] input) { //Computes message digest
        update(input);
        initHashValues();
        padding();
        
        //The eight working variables
        long a;
        long b;
        long c;
        long d;
        long e;
        long f;
        long g;
        long h;
        
        //Temporary variables
        long t1;
        long t2;
        
        //For each byte array in data
        for (int dataIndex = 0; dataIndex < data.size(); dataIndex++) {
            parsing(dataIndex);
            for (int i = 0; i < blocks; i++) {
                //Prepares message schedule
                for (int t = 0; t < 80; t++) {
                    if (t <= 15) {
                        w[t] = m[i][t];
                    }
                    else {
                        w[t] = l_sigma1(w[t-2]) + w[t-7] + l_sigma0(w[t-15]) + w[t-16];
                    }
                }
                
                //Initialize working variables
                a = h0;
                b = h1;
                c = h2;
                d = h3;
                e = h4;
                f = h5;
                g = h6;
                h = h7;

                for (int t = 0; t < 80; t++) {
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
                
                //Final hash values for block
                h0 += a;
                h1 += b;
                h2 += c;
                h3 += d;
                h4 += e;
                h5 += f;
                h6 += g;
                h7 += h;
            }
        }
        
        data = new ArrayList<>(); //Clears data array list
        
        //Prepares message digest as a single 512-bit byte array
        ByteBuffer buffer = ByteBuffer.allocate(64);
        buffer.putLong(h0);
        buffer.putLong(h1);
        buffer.putLong(h2);
        buffer.putLong(h3);
        buffer.putLong(h4);
        buffer.putLong(h5);
        buffer.putLong(h6);
        buffer.putLong(h7);
        byte[] digest = buffer.array(); //512-bit message digest
        return digest;
    }
    
    private long rotateRight(long x, int n) { //Circular right shift (x: Integer, n: Shift value)
        return (x >>> n) | (x << (64-n));
    }
    
    //SHA-512 Functions
    
    private long ch(long x, long y, long z) {
        return (x & y) ^ (~x & z);
    }
    
    private long maj(long x, long y, long z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    private long sigma0(long x) {
        return rotateRight(x, 28) ^ rotateRight(x, 34) ^ rotateRight(x, 39);
    }
    
    private long sigma1(long x) {
        return rotateRight(x, 14) ^ rotateRight(x, 18) ^ rotateRight(x, 41);
    }
    
    private long l_sigma0(long x) {
        return rotateRight(x, 1) ^ rotateRight(x, 8) ^ (x >>> 7);
    }
    
    private long l_sigma1(long x) {
        return rotateRight(x, 19) ^ rotateRight(x, 61) ^ (x >>> 6);
    }
    
}
