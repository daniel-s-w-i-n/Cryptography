package uk.ac.nottingham.cryptography.ciphers;

public class Zodiac implements ZodiacCipher, BlockCipher {
    public static final byte[] S1 = {
            (byte) 0x2d, (byte) 0xf3, (byte) 0x7c, (byte) 0x6d, (byte) 0x9d, (byte) 0xb5, (byte) 0x26, (byte) 0x74,
            (byte) 0xf2, (byte) 0x93, (byte) 0x53, (byte) 0xb0, (byte) 0xf0, (byte) 0x11, (byte) 0xed, (byte) 0x83,
            (byte) 0x78, (byte) 0xb6, (byte) 0x03, (byte) 0x16, (byte) 0x73, (byte) 0x3b, (byte) 0x1e, (byte) 0x8e,
            (byte) 0x70, (byte) 0xbd, (byte) 0x86, (byte) 0x1b, (byte) 0x47, (byte) 0x7e, (byte) 0x24, (byte) 0x56,
            (byte) 0xf1, (byte) 0x77, (byte) 0x88, (byte) 0x46, (byte) 0x97, (byte) 0xb1, (byte) 0xba, (byte) 0xa3,
            (byte) 0xb7, (byte) 0x10, (byte) 0x0a, (byte) 0xc5, (byte) 0x37, (byte) 0xb3, (byte) 0xc9, (byte) 0x5a,
            (byte) 0x28, (byte) 0xac, (byte) 0x64, (byte) 0xa5, (byte) 0xec, (byte) 0xab, (byte) 0xaa, (byte) 0xc6,
            (byte) 0x67, (byte) 0x95, (byte) 0x58, (byte) 0x0d, (byte) 0xf8, (byte) 0x9a, (byte) 0xf6, (byte) 0x6e,
            (byte) 0x66, (byte) 0xdc, (byte) 0x05, (byte) 0x3d, (byte) 0xd3, (byte) 0x8a, (byte) 0xc3, (byte) 0xd8,
            (byte) 0x89, (byte) 0x6a, (byte) 0xe9, (byte) 0x36, (byte) 0x49, (byte) 0x43, (byte) 0xbf, (byte) 0xeb,
            (byte) 0xd4, (byte) 0x96, (byte) 0x9b, (byte) 0x68, (byte) 0xa0, (byte) 0x65, (byte) 0x5d, (byte) 0x57,
            (byte) 0x92, (byte) 0x1f, (byte) 0xd5, (byte) 0x71, (byte) 0x5c, (byte) 0xbb, (byte) 0x22, (byte) 0xc1,
            (byte) 0xbe, (byte) 0x7b, (byte) 0xbc, (byte) 0x99, (byte) 0x63, (byte) 0x94, (byte) 0x5f, (byte) 0x2a,
            (byte) 0x61, (byte) 0xb8, (byte) 0x34, (byte) 0x32, (byte) 0x19, (byte) 0xfd, (byte) 0xfb, (byte) 0x17,
            (byte) 0x40, (byte) 0xe6, (byte) 0x51, (byte) 0x1d, (byte) 0x41, (byte) 0x44, (byte) 0x8f, (byte) 0x29,
            (byte) 0xdd, (byte) 0x04, (byte) 0x80, (byte) 0xde, (byte) 0xe7, (byte) 0x31, (byte) 0xd6, (byte) 0x7f,
            (byte) 0x01, (byte) 0xa2, (byte) 0xf7, (byte) 0x39, (byte) 0xda, (byte) 0x6f, (byte) 0x23, (byte) 0xca,
            (byte) 0xfe, (byte) 0x3a, (byte) 0xd0, (byte) 0x1c, (byte) 0xd1, (byte) 0x30, (byte) 0x3e, (byte) 0x12,
            (byte) 0xa1, (byte) 0xcd, (byte) 0x0f, (byte) 0xe0, (byte) 0xa8, (byte) 0xaf, (byte) 0x82, (byte) 0x59,
            (byte) 0x2c, (byte) 0xf5, (byte) 0x7d, (byte) 0xad, (byte) 0xb2, (byte) 0xef, (byte) 0xc2, (byte) 0x87,
            (byte) 0xce, (byte) 0x75, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x90, (byte) 0x4f, (byte) 0x2e,
            (byte) 0x72, (byte) 0x33, (byte) 0x85, (byte) 0xc0, (byte) 0x8d, (byte) 0xcf, (byte) 0xa9, (byte) 0x81,
            (byte) 0xe2, (byte) 0xc4, (byte) 0x27, (byte) 0x2f, (byte) 0x6c, (byte) 0x7a, (byte) 0x9f, (byte) 0x52,
            (byte) 0xe1, (byte) 0x15, (byte) 0x38, (byte) 0x2b, (byte) 0xfc, (byte) 0x20, (byte) 0x42, (byte) 0xc7,
            (byte) 0x08, (byte) 0xe4, (byte) 0x09, (byte) 0x55, (byte) 0x5e, (byte) 0x8c, (byte) 0x14, (byte) 0x76,
            (byte) 0x60, (byte) 0xff, (byte) 0xdf, (byte) 0xd7, (byte) 0x98, (byte) 0xfa, (byte) 0x0b, (byte) 0x21,
            (byte) 0x00, (byte) 0x1a, (byte) 0xf9, (byte) 0xa6, (byte) 0xb9, (byte) 0xe8, (byte) 0x9e, (byte) 0x62,
            (byte) 0x4c, (byte) 0xd9, (byte) 0x91, (byte) 0x50, (byte) 0xd2, (byte) 0xee, (byte) 0x18, (byte) 0xb4,
            (byte) 0x07, (byte) 0x84, (byte) 0xea, (byte) 0x5b, (byte) 0xa4, (byte) 0xc8, (byte) 0x0e, (byte) 0xcb,
            (byte) 0x48, (byte) 0x69, (byte) 0x4b, (byte) 0x4e, (byte) 0x9c, (byte) 0x35, (byte) 0x79, (byte) 0x45,
            (byte) 0x4d, (byte) 0x54, (byte) 0xe5, (byte) 0x25, (byte) 0x3c, (byte) 0x0c, (byte) 0x4a, (byte) 0x8b,
            (byte) 0x3f, (byte) 0xcc, (byte) 0xa7, (byte) 0xdb, (byte) 0x6b, (byte) 0xae, (byte) 0xf4, (byte) 0xe3
    };

    public static final byte[] S2 = {
            (byte) 0x12, (byte) 0x4a, (byte) 0x26, (byte) 0xc8, (byte) 0xd2, (byte) 0x62, (byte) 0xce, (byte) 0xe7,
            (byte) 0x2e, (byte) 0xc3, (byte) 0xfb, (byte) 0x7c, (byte) 0x65, (byte) 0x48, (byte) 0x8f, (byte) 0xb8,
            (byte) 0x76, (byte) 0x3d, (byte) 0xa5, (byte) 0x8e, (byte) 0x86, (byte) 0x57, (byte) 0xbd, (byte) 0xbc,
            (byte) 0x1f, (byte) 0xef, (byte) 0x0c, (byte) 0xe0, (byte) 0x78, (byte) 0x71, (byte) 0x11, (byte) 0x75,
            (byte) 0x95, (byte) 0xd9, (byte) 0x9b, (byte) 0x9e, (byte) 0xb9, (byte) 0xa4, (byte) 0xf7, (byte) 0x02,
            (byte) 0x7f, (byte) 0x80, (byte) 0x83, (byte) 0x7e, (byte) 0xbe, (byte) 0x56, (byte) 0x96, (byte) 0x73,
            (byte) 0x9f, (byte) 0x88, (byte) 0x2a, (byte) 0x14, (byte) 0x89, (byte) 0x9a, (byte) 0xf9, (byte) 0xdc,
            (byte) 0x32, (byte) 0x6d, (byte) 0xde, (byte) 0x6a, (byte) 0x84, (byte) 0x72, (byte) 0xd8, (byte) 0x8a,
            (byte) 0xd7, (byte) 0xe3, (byte) 0x08, (byte) 0x4e, (byte) 0x1e, (byte) 0xb3, (byte) 0x5d, (byte) 0x50,
            (byte) 0xd6, (byte) 0xeb, (byte) 0xb1, (byte) 0x0d, (byte) 0xcf, (byte) 0xad, (byte) 0xc6, (byte) 0x0e,
            (byte) 0x7d, (byte) 0xa0, (byte) 0xdd, (byte) 0x9c, (byte) 0x41, (byte) 0x1c, (byte) 0xcd, (byte) 0x1a,
            (byte) 0x38, (byte) 0x34, (byte) 0x5b, (byte) 0x23, (byte) 0x03, (byte) 0x8c, (byte) 0x68, (byte) 0x46,
            (byte) 0x53, (byte) 0x04, (byte) 0xa9, (byte) 0x27, (byte) 0xac, (byte) 0xe6, (byte) 0x1b, (byte) 0xfc,
            (byte) 0x2f, (byte) 0xa3, (byte) 0x0b, (byte) 0x28, (byte) 0xe4, (byte) 0x0f, (byte) 0xda, (byte) 0xd4,
            (byte) 0xc4, (byte) 0xd5, (byte) 0x94, (byte) 0x8b, (byte) 0x90, (byte) 0x6b, (byte) 0x9d, (byte) 0xf8,
            (byte) 0xae, (byte) 0x63, (byte) 0x7a, (byte) 0x07, (byte) 0xe2, (byte) 0xea, (byte) 0xc5, (byte) 0xdb,
            (byte) 0x98, (byte) 0x15, (byte) 0xc1, (byte) 0x0a, (byte) 0xa2, (byte) 0xc2, (byte) 0x30, (byte) 0x44,
            (byte) 0x5a, (byte) 0xf1, (byte) 0x3a, (byte) 0x6e, (byte) 0xa8, (byte) 0xc9, (byte) 0x55, (byte) 0x4d,
            (byte) 0x20, (byte) 0x6f, (byte) 0xf2, (byte) 0x35, (byte) 0x59, (byte) 0x19, (byte) 0x77, (byte) 0xbb,
            (byte) 0x92, (byte) 0x6c, (byte) 0x2c, (byte) 0x45, (byte) 0x66, (byte) 0x42, (byte) 0xf3, (byte) 0x39,
            (byte) 0x29, (byte) 0xc0, (byte) 0xe8, (byte) 0x4f, (byte) 0xe5, (byte) 0xc7, (byte) 0xb0, (byte) 0xe1,
            (byte) 0x8d, (byte) 0xf6, (byte) 0x00, (byte) 0x01, (byte) 0x7b, (byte) 0xd1, (byte) 0xcb, (byte) 0x52,
            (byte) 0xfd, (byte) 0xcc, (byte) 0x58, (byte) 0x3f, (byte) 0xee, (byte) 0xb2, (byte) 0xff, (byte) 0x40,
            (byte) 0xaa, (byte) 0x4b, (byte) 0x74, (byte) 0xb4, (byte) 0x60, (byte) 0x5f, (byte) 0x99, (byte) 0x2b,
            (byte) 0x91, (byte) 0xdf, (byte) 0xf4, (byte) 0x47, (byte) 0x21, (byte) 0x3b, (byte) 0x33, (byte) 0x93,
            (byte) 0xaf, (byte) 0xd3, (byte) 0x16, (byte) 0x5e, (byte) 0x36, (byte) 0x43, (byte) 0x49, (byte) 0xa6,
            (byte) 0xd0, (byte) 0x06, (byte) 0xb6, (byte) 0x70, (byte) 0x81, (byte) 0x82, (byte) 0xa1, (byte) 0xfa,
            (byte) 0x97, (byte) 0x85, (byte) 0x79, (byte) 0xb7, (byte) 0xba, (byte) 0x3c, (byte) 0x10, (byte) 0xb5,
            (byte) 0xab, (byte) 0x13, (byte) 0xa7, (byte) 0x64, (byte) 0xe9, (byte) 0x09, (byte) 0x54, (byte) 0x25,
            (byte) 0x37, (byte) 0x67, (byte) 0x1d, (byte) 0xfe, (byte) 0xf5, (byte) 0x69, (byte) 0x2d, (byte) 0x31,
            (byte) 0x22, (byte) 0xf0, (byte) 0x18, (byte) 0x3e, (byte) 0x61, (byte) 0x17, (byte) 0x51, (byte) 0xec,
            (byte) 0x05, (byte) 0xca, (byte) 0xed, (byte) 0x5c, (byte) 0x87, (byte) 0xbf, (byte) 0x4c, (byte) 0x24
    };

    public static final int[] M = {
            0xbdba3bed,
            0xf36e6b11,
            0xcefb0d59,
            0x111ef1f1,
            0x72fc76bb,
            0xacb44526,
            0x9a26714f,
            0x37d81f7b
    };

    public byte[][] keys;

    public int[] appendByteList(byte[] list,int numOfIntegers){
        int[] appendedBytes = new int[numOfIntegers];

        //appends each byte into an integer and stores in an int[]
        for (int i = 0; i< numOfIntegers; i ++){
            appendedBytes[i] =
                    list[i*4 + 0]<<24 |
                    list[i*4 + 1]<<16 &0xFFFFFF |
                    list[i*4 + 2]<<8 &0xFFFF |
                    list[i*4 + 3] &0xFF;
        }
        return appendedBytes;
    }

    public int appendBytes(byte a,byte b, byte c, byte d){
        return a<<24 |b<<16 &0xFFFFFF |c<<8 &0xFFFF |d &0xFF;
    }

    public void reallocateBytes(int startIndex, int word, byte[] block){
        block[startIndex] = (byte) (word >> 24);
        block[startIndex+1] = (byte) (word>>16);
        block[startIndex+2] = (byte) (word>>8);
        block[startIndex+3] = (byte) (word);
    }

    public void reallocateWords(int length, int[] word, byte[] block){

        for(int i = 0; i < length/4; i++){
            block[i*4] = (byte) (word[i] >> 24);
            block[i*4+1] = (byte) (word[i]>>16);
            block[i*4+2] = (byte) (word[i]>>8);
            block[i*4+3] = (byte) (word[i]);
        }
    }

    //linear mixing of bytes within 64 bit half block
    @Override
    public void F(byte[] block) {

        //put into block[i] to reduce temporary variables
        //xor block backwards as not to overwrite blocks with xor value
        for(int i=7; i>0;i--){
            if(i != 4) {
                block[i] = (byte) (block[i - 1] ^ block[i]);
            }
        }

        //storing A^H so it can be put in E
        int tempE = block[7]^block[0];

        block[0] = S1[(block[3]^block[4]) &0xFF];

        // use S-boxes on alternating bytes excluding 4
        for (int i = 1; i < 8; i++){
            if(i == 4){
                block[4] = S1[tempE &0xFF];
            }
            else if(i%2 == 0){
                block[i] = S1[block[i] &0xFF];
            }
            else{
                block[i] = S2[block[i] &0xFF];
            }
        }

    }

    //padding
    @Override
    public void initPads(byte[] dpad, byte[] kpad, byte[] key) {

        int[] dpadKey = new int[4];
        int[] kpadKey = new int[4];

        //add key bytes together to create 32 bit word
        int[] keys = appendByteList(key,4);

        //xor key with M [0-3]
        dpadKey[0] = (keys[2]^M[2]);
        dpadKey[1] = (keys[0]^M[0]);
        dpadKey[2] = (keys[3]^M[3]);
        dpadKey[3] = (keys[1]^M[1]);

        //allocate to dpad
        reallocateWords(16,dpadKey,dpad);

        //xor dpad with M [4-7]
        kpadKey[0] = (dpadKey[1]^M[5]);
        kpadKey[1] = (dpadKey[0]^M[4]);
        kpadKey[2] = (dpadKey[3]^M[7]);
        kpadKey[3] = (dpadKey[2]^M[6]);

        //allocate to kpad
        reallocateWords(16,kpadKey,kpad);

    }

    //mixing operation
    @Override
    public void PI(byte[] block) {

        //add bytes together to create 32 bit word
        int[] PII = appendByteList(block,4);

        //use xor to permutate
        int T = (PII[0]^PII[1]^PII[2]^PII[3]);
        for(int i = 0; i<4;i++){
            PII[i] = (PII[i]^T);
        }

        //reallocate bytes to blocks
        reallocateWords(16,PII,block);

    }

    @Override
    public void PSI(byte[] block) {

        //initialize blocks = 8 bytes
        byte[] leftBlock = new byte[8];
        byte[] rightBlock = new byte[8];

        byte[] blockTemp = new byte[8];

        //copy block halves into arrays leftBlock and rightBlock
        System.arraycopy(block ,0,leftBlock,0,8);
        System.arraycopy(block ,8,rightBlock,0,8);
        System.arraycopy(block ,0,blockTemp,0,8);

        F(leftBlock);

        PSIBlockSwap(rightBlock,leftBlock,rightBlock);

        System.arraycopy(rightBlock ,0,leftBlock,0,8);

        F(rightBlock);

        PSIBlockSwap(blockTemp,rightBlock,leftBlock);

        //copy finished PSI into block
        System.arraycopy(leftBlock,0,block,0,8);
        System.arraycopy(rightBlock,0,block,8,8);

    }

    //xors block 1 and 2 and then reallocates it to bytes
    public void PSIBlockSwap(byte[] blockOne,byte[] blockTwo,byte[] blockReallocate){
        int[] intBlock1 = appendByteList(blockOne,2);
        int[] intBlock2 = appendByteList(blockTwo,2);

        //saves the state of blockTwo in blockRelocate
        System.arraycopy(blockReallocate ,0,blockTwo,0,8);

        //blockOne = blockOne^blockTwo;
        intBlock1[0] = intBlock2[0]^intBlock1[0];
        intBlock1[1] = intBlock2[1]^intBlock1[1];

        reallocateWords(8,intBlock1,blockReallocate);

    }

    @Override
    public byte[][] generateSchedule(byte[] dpad, byte[] kpad) {

        byte[][] ki = new byte[18][8];
        byte[] round = new byte[16];  //could use kpad instead because it isnt used until allocated too
        for (int i = 0;i<18 ;i++)
        {
            PI(dpad);

            //add dpad and kpad bytes into 32 bit words
            int[] dpadInts = appendByteList(dpad,4);
            int[] kpadInts = appendByteList(kpad,4);

            //xor kpad and dpad
            for(int j = 0; j < 4; j++){
                dpadInts[j] = dpadInts[j]^kpadInts[j];
            }

            //dpad = kpad and round = kpad xor dpad
            reallocateWords(16,kpadInts,dpad);
            reallocateWords(16,dpadInts,round);

            PSI(round);

            //xor kpad values with constants L to get new values
            kpadInts = appendByteList(round,4);
            for(int k = 0; k<4; k++){
                kpadInts[k] = kpadInts[k] ^ ((i*4+16+k) % 256);
            }
            reallocateWords(16,kpadInts,kpad);

            //allocate key at position i
            for(int l = 0; l<8;l++){
                ki[i][l] = kpad[l];
            }
        }
        return ki;
    }

    @Override
    public void initialise(byte[] key) {
        byte[] dpads = new byte[16];
        byte[] kpads = new byte[16];

        initPads(dpads,kpads,key);
        keys = generateSchedule(dpads,kpads);
    }

    @Override
    public void encrypt(byte[] input, byte[] output) {

        byte[] x = new byte[16];
        System.arraycopy(input,0,x,0,16);

        PI(x);

        byte[] tempBlock = new byte[64];

        //leftBlock into ints
        int leftSideIntOne = appendBytes(x[0], x[1], x[2], x[3]);
        int leftSideIntTwo = appendBytes(x[4], x[5], x[6], x[7]);
        //rightBlock into ints
        int rightSideIntOne = appendBytes(x[8], x[9], x[10], x[11]);
        int rightSideIntTwo = appendBytes(x[12], x[13], x[14], x[15]);
        int a,b;


        //whole key into words
        a = appendBytes(keys[0][0], keys[0][1], keys[0][2], keys[0][3]);
        b = appendBytes(keys[0][4], keys[0][5], keys[0][6], keys[0][7]);

        leftSideIntOne = a^leftSideIntOne;
        leftSideIntTwo = b^leftSideIntTwo;

        for (int i = 1;i < 16; i+=2) {

            a = appendBytes(keys[i][0], keys[i][1], keys[i][2], keys[i][3]);
            b = appendBytes(keys[i][4], keys[i][5], keys[i][6], keys[i][7]);

            //reallocate block to put through F
            reallocateBytes(0, a ^ leftSideIntOne, tempBlock);
            reallocateBytes(4, b ^ leftSideIntTwo, tempBlock);
            F(tempBlock);

            //TEMPbLOCK to int
            a = appendBytes(tempBlock[0], tempBlock[1], tempBlock[2], tempBlock[3]);
            b = appendBytes(tempBlock[4], tempBlock[5], tempBlock[6], tempBlock[7]);

            rightSideIntOne = a ^ rightSideIntOne;
            rightSideIntTwo = b ^ rightSideIntTwo;

            a = appendBytes(keys[i+1][0], keys[i+1][1], keys[i+1][2], keys[i+1][3]);
            b = appendBytes(keys[i+1][4], keys[i+1][5], keys[i+1][6], keys[i+1][7]);

            //reallocate block to put through F
            reallocateBytes(0, a ^ rightSideIntOne, tempBlock);
            reallocateBytes(4, b ^ rightSideIntTwo, tempBlock);
            F(tempBlock);

            //TEMPbLOCK to int
            a = appendBytes(tempBlock[0], tempBlock[1], tempBlock[2], tempBlock[3]);
            b = appendBytes(tempBlock[4], tempBlock[5], tempBlock[6], tempBlock[7]);
            //xor with left
            leftSideIntOne = a ^ leftSideIntOne;
            leftSideIntTwo = b ^ leftSideIntTwo;
        }

        a = appendBytes(keys[17][0], keys[17][1], keys[17][2], keys[17][3]);
        b = appendBytes(keys[17][4], keys[17][5], keys[17][6], keys[17][7]);

        rightSideIntOne = a^rightSideIntOne;
        rightSideIntTwo = b^rightSideIntTwo;

        reallocateBytes(0, rightSideIntOne, output);
        reallocateBytes(4, rightSideIntTwo, output);
        reallocateBytes(8, leftSideIntOne, output);
        reallocateBytes(12, leftSideIntTwo, output);

        PI(output);
    }

    @Override
    public void decrypt(byte[] input, byte[] output) {

        PI(input);

        byte[] tempBlock = new byte[64];

        //leftBlock into ints
        int leftSideIntOne = appendBytes(input[0], input[1], input[2], input[3]);
        int leftSideIntTwo = appendBytes(input[4], input[5], input[6], input[7]);
        //rightBlock into ints
        int rightSideIntOne = appendBytes(input[8], input[9], input[10], input[11]);
        int rightSideIntTwo = appendBytes(input[12], input[13], input[14], input[15]);
        int a,b;


        //whole key into words
        a = appendBytes(keys[17][0], keys[17][1], keys[17][2], keys[17][3]);
        b = appendBytes(keys[17][4], keys[17][5], keys[17][6], keys[17][7]);

        leftSideIntOne = a^leftSideIntOne;
        leftSideIntTwo = b^leftSideIntTwo;

        for (int i = 16;i > 1; i-=2) {

            a = appendBytes(keys[i][0], keys[i][1], keys[i][2], keys[i][3]);
            b = appendBytes(keys[i][4], keys[i][5], keys[i][6], keys[i][7]);

            //reallocate block to put through F
            reallocateBytes(0, a ^ leftSideIntOne, tempBlock);
            reallocateBytes(4, b ^ leftSideIntTwo, tempBlock);
            F(tempBlock);

            //TEMPbLOCK to int
            a = appendBytes(tempBlock[0], tempBlock[1], tempBlock[2], tempBlock[3]);
            b = appendBytes(tempBlock[4], tempBlock[5], tempBlock[6], tempBlock[7]);

            rightSideIntOne = a ^ rightSideIntOne;
            rightSideIntTwo = b ^ rightSideIntTwo;

            a = appendBytes(keys[i-1][0], keys[i-1][1], keys[i-1][2], keys[i-1][3]);
            b = appendBytes(keys[i-1][4], keys[i-1][5], keys[i-1][6], keys[i-1][7]);

            //reallocate block to put through F
            reallocateBytes(0, a ^ rightSideIntOne, tempBlock);
            reallocateBytes(4, b ^ rightSideIntTwo, tempBlock);
            F(tempBlock);

            //TEMPbLOCK to int
            a = appendBytes(tempBlock[0], tempBlock[1], tempBlock[2], tempBlock[3]);
            b = appendBytes(tempBlock[4], tempBlock[5], tempBlock[6], tempBlock[7]);
            //xor with left
            leftSideIntOne = a ^ leftSideIntOne;
            leftSideIntTwo = b ^ leftSideIntTwo;
        }

        a = appendBytes(keys[0][0], keys[0][1], keys[0][2], keys[0][3]);
        b = appendBytes(keys[0][4], keys[0][5], keys[0][6], keys[0][7]);

        rightSideIntOne = a^rightSideIntOne;
        rightSideIntTwo = b^rightSideIntTwo;

        reallocateBytes(0, rightSideIntOne, output);
        reallocateBytes(4, rightSideIntTwo, output);
        reallocateBytes(8, leftSideIntOne, output);
        reallocateBytes(12, leftSideIntTwo, output);

        PI(output);
    }

}
