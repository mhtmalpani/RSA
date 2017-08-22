package Examples;

import RSAhelper.RSA;

public class ExampleSimple {

    public static void main(String[] args) {

        RSA rsa = new RSA(256);

        String plainText = "Hello World!";
        String cipherText = rsa.encrypt(plainText);


        System.out.println("PlainText: " + plainText);
        System.out.println("CipherText: " + cipherText);
        System.out.println();

        System.out.println("Modulus     (N): " + rsa.getModulus());
        System.out.println("Public Key  (E): " + rsa.getPublicKeyExponent());
        System.out.println("Private Key (D): " + rsa.getPrivateKeyExponent());
        System.out.println();

        String encryptedMessage = rsa.decrypt(cipherText);
        System.out.println("Decrypted plainText: " + encryptedMessage);
    }
}
