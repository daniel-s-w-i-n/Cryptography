package uk.ac.nottingham.cryptography.modes;

import uk.ac.nottingham.cryptography.ciphers.BlockCipher;
import uk.ac.nottingham.cryptography.ciphers.ZodiacCipher;
import uk.ac.nottingham.cryptography.galois.GF128Multiplier;

import java.util.function.Supplier;



public class XTSMode implements TweakableCipherMode {

    BlockCipher zodiacEKE;
    BlockCipher zodiacEKT;
    byte[] Ti = new byte[16];

    public int[] appendByteList(byte[] list,int numOfIntegers,int index){
        int[] appendedBytes = new int[numOfIntegers];

        //appends each byte into an integer and stores in an int[]
        for (int i = 0; i< numOfIntegers; i ++){
            appendedBytes[i] =
                    list[i * 4 + index]<<24 |
                    list[i*4 + index + 1]<<16 &0xFFFFFF |
                    list[i*4 + index + 2]<<8 &0xFFFF |
                    list[i*4 + index + 3] &0xFF;
        }
        return appendedBytes;
    }

    public void reallocateWords(int length, int[] word, byte[] block, int index){

        for(int i = 0; i < length/4; i++){
            block[index + i*4] = (byte) (word[i] >> 24);
            block[index + i*4+1] = (byte) (word[i]>>16);
            block[index + i*4+2] = (byte) (word[i]>>8);
            block[index + i*4+3] = (byte) (word[i]);
        }
    }

    @Override
    public void initialise(Supplier<BlockCipher> cipherSupplier, byte[] key) {

        zodiacEKT = cipherSupplier.get();
        zodiacEKE = cipherSupplier.get();
        byte[] Eke = new byte[16];
        System.arraycopy(key,0,Eke,0,16);
        byte[] Ekt = new byte[16];
        System.arraycopy(key,16,Ekt,0,16);

        zodiacEKT.initialise(Ekt);
        zodiacEKE.initialise(Eke);
    }

    private void byteEncryptDecrypt(byte[] data, int index, byte[] PxorT, boolean encrypt){

        //allocate 32 bytes to 4 ints
        int[] dataInts = appendByteList(data,4 , 16 * index);
        int[] tiInts = appendByteList(Ti,4 , 0);

        for(int i = 0; i<4 ; i ++){
            dataInts[i] = dataInts[i]^tiInts[i];
        }
        reallocateWords(16,dataInts,PxorT,0);

        //encrypt or decrypt
        if(encrypt) {
            zodiacEKE.encrypt(PxorT, PxorT);
        }else{
            zodiacEKE.decrypt(PxorT,PxorT);
        }

        //reallocate changed PxorT
        dataInts = appendByteList(PxorT,4 , 0);

        for(int i = 0; i<4 ; i ++){
            dataInts[i] = dataInts[i]^tiInts[i];
        }
        reallocateWords(16, dataInts, data, 16 * index);

    }

    private void encryptDecryptLastByteAndSwap(byte[] data, int dataRemaining,byte[] PxorT, boolean encryptOrDecrypt){

        byte[] finalByte = new byte[16];
        int length = data.length;

        System.arraycopy(data,length-dataRemaining,finalByte,0,dataRemaining);
        for (int i = 1; i < (16-dataRemaining+1);i++){
            finalByte[16-i] = data[16*(length/16) - i];
        }
        byteEncryptDecrypt(finalByte,0,PxorT,encryptOrDecrypt);

        //copy Pm to end
        //then copy finalByte into Pm-1
        System.arraycopy(data,length-(16+dataRemaining),data,length-dataRemaining,dataRemaining);
        System.arraycopy(finalByte,0,data,length-(16+dataRemaining),16);
    }

    @Override
    public void encrypt(byte[] sector, byte[] data) {

        byte[] PxorT = new byte[16];
        int dataRemaining = data.length %16;

        //create Ti and multiplier
        zodiacEKT.encrypt(sector,Ti);
        GF128Multiplier multiplier = new GF128Multiplier();

        //Full block encryption
        for (int i = 0; i < (data.length / 16); i++) {

            byteEncryptDecrypt(data,i,PxorT,true);
            //increments to Ti+1
            multiplier.multiplyByX(Ti);
        }

        //Partial block encryption
        if(dataRemaining != 0){

            encryptDecryptLastByteAndSwap(data,dataRemaining,PxorT, true);
        }
    }

    @Override
    public void decrypt(byte[] sector, byte[] data) {

        byte[] PxorT = new byte[16];
        int dataRemaining = data.length %16;

        //create Ti and multiplier
        zodiacEKT.encrypt(sector,Ti);
        GF128Multiplier multiplier = new GF128Multiplier();

        //Full blocks
        for (int i = 0; i < (data.length / 16)-1; i++) {

            byteEncryptDecrypt(data,i,PxorT,false);
            //increments to Ti+1
            multiplier.multiplyByX(Ti);
        }

        //Partial block
        if(dataRemaining != 0){
            //save Tm-1
            byte[] Tpenultimate = new byte[32];
            System.arraycopy(Ti,0,Tpenultimate,0,16);

            //makes Ti Tm and uses it to decrypt
            multiplier.multiplyByX(Ti);
            byteEncryptDecrypt(data,(data.length / 16)-1,PxorT,false);
            System.arraycopy(Tpenultimate,0,Ti,0,16);

            encryptDecryptLastByteAndSwap(data,dataRemaining,PxorT, false);

        } else{
            //encrypt last block if there is no partial block
            byteEncryptDecrypt(data,(data.length / 16)-1,PxorT,false);
        }

    }
}
