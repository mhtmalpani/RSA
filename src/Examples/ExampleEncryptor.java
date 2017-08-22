package Examples;

import RSAhelper.RSA;

public class ExampleEncryptor {

    public static void main(String[] args) {

        RSA rsa = new RSA(256);

        String plainText = "Hello World!";
        String modulus = "82468643682789593970543234154887965728854003696403950953903146794246440489531";
        String publicKeyExponent = "5";

        String cipherText = rsa.encrypt(plainText, modulus, publicKeyExponent);


        System.out.println("PlainText  : " + plainText);
        System.out.println("CipherText : " + cipherText);
        System.out.println();

        System.out.println("Modulus     (N): " + rsa.getModulus());
        System.out.println("Public Key  (E): " + rsa.getPublicKeyExponent());
        System.out.println();
    }
}
