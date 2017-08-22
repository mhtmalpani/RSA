package Examples;

import RSAhelper.RSA;

public class ExampleDecryptor {

    public static void main(String[] args) {

        RSA rsa = new RSA();

        String cipherText = "3383471816938404359640631606807524173564077793903728588994415846166091451188";
        String modulus = "82468643682789593970543234154887965728854003696403950953903146794246440489531";
        String privateKey = "32987457473115837588217293661955186291311797040351886579048799884996838093149";

        String plainText = rsa.decrypt(cipherText, modulus, privateKey);

        System.out.println("Decrypted PlainText: " + plainText);
    }
}
