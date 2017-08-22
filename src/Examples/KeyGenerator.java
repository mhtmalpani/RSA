package Examples;

import RSAhelper.KeyPairGenerator;
import RSAhelper.RSA;

import java.security.KeyPair;

public class KeyGenerator {

    public static void main(String[] args) {

        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        //                               KeyPairGenerator 256 bits                                             //
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        KeyPairGenerator rsa256 = new KeyPairGenerator(256);

        System.out.println("Modulus      (N): " + rsa256.getModulus());
        System.out.println("Public Key   (E): " + rsa256.getPublicKeyExponent());
        System.out.println("Private Key  (D): " + rsa256.getPrivateKeyExponent());
        System.out.println();


        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        //                               KeyPairGenerator 512 bits                                             //
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        KeyPairGenerator rsa512 = new KeyPairGenerator();

        System.out.println("Modulus      (N): " + rsa512.getModulus());
        System.out.println("Public Key   (E): " + rsa512.getPublicKeyExponent());
        System.out.println("Private Key  (D): " + rsa512.getPrivateKeyExponent());
        System.out.println();


        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        //                               KeyPairGenerator 1024 bits                                            //
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        KeyPairGenerator rsa1024 = new KeyPairGenerator(1024);

        System.out.println("Modulus      (N): " + rsa1024.getModulus());
        System.out.println("Public Key   (E): " + rsa1024.getPublicKeyExponent());
        System.out.println("Private Key  (D): " + rsa1024.getPrivateKeyExponent());
        System.out.println();


        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        //                               KeyPairGenerator 2048 bits                                            //
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        KeyPairGenerator rsa2048 = new KeyPairGenerator(2048);

        System.out.println("Modulus      (N): " + rsa2048.getModulus());
        System.out.println("Public Key   (E): " + rsa2048.getPublicKeyExponent());
        System.out.println("Private Key  (D): " + rsa2048.getPrivateKeyExponent());
        System.out.println();

        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        //                               KeyPairGenerator 512 bits                                             //
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        KeyPairGenerator rsa512Exponent35 = new KeyPairGenerator(512, 35);

        System.out.println("Modulus      (N): " + rsa512Exponent35.getModulus());
        System.out.println("Public Key   (E): " + rsa512Exponent35.getPublicKeyExponent());
        System.out.println("Private Key  (D): " + rsa512Exponent35.getPrivateKeyExponent());
        System.out.println();


        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        //                               KeyPairGenerator 256 bits                                             //
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        KeyPairGenerator rsa512ExponentSecure = new KeyPairGenerator(256, Math.toIntExact((long) (Math.pow(2, 16) + 1)));

        System.out.println("Modulus      (N): " + rsa512ExponentSecure.getModulus());
        System.out.println("Public Key   (E): " + rsa512ExponentSecure.getPublicKeyExponent());
        System.out.println("Private Key  (D): " + rsa512ExponentSecure.getPrivateKeyExponent());
        System.out.println();
    }
}
