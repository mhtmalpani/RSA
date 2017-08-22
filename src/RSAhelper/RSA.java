package RSAhelper;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {

    //Prime 1
    private BigInteger p;

    //Prime 2
    private BigInteger q;

    //Modulus
    private BigInteger n;

    //Totient: Phi(n)
    private BigInteger m;

    //Public Key Exponent
    private BigInteger e;

    //Private Key Exponent
    private BigInteger d;

    //Bit Length
    private int bitLength;


    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          Constructors                                               //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * Default Constructor with default value settings
     */
    public RSA() {
        //Default Bit Length
        this(512);
    }

    /**
     * Overload Constructor
     *
     * @param bitLength user specified computation bitlength
     */
    public RSA(int bitLength) {
        this.bitLength = bitLength;

        //Default start value for public key exponent
        this.e = new BigInteger("3");

        prepareAlgorithmDependencies();
    }

    /**
     * Overload Constructor
     *
     * @param bitLength                 user specified computation bitlength
     * @param publicKeyExponentMinValue minimum exponent number
     */
    public RSA(int bitLength, int publicKeyExponentMinValue) {
        this.bitLength = bitLength;
        this.e = new BigInteger(String.valueOf(publicKeyExponentMinValue));

        prepareAlgorithmDependencies();
    }

    /**
     * Overload Constructor
     * Pass the Public key
     * <p>
     * Should only use the Encryption when this constructor is used
     *
     * @param modulus           Modulus provided for computation
     * @param publicKeyExponent Public Key Exponent for computation
     */
    public RSA(String modulus, String publicKeyExponent) {
        this.n = new BigInteger(modulus);
        this.e = new BigInteger(publicKeyExponent);
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       Algorithm Helper                                              //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////


    /**
     * Prepares the steps related to generation of Keys to set up
     * the Encryption and Decryption environment
     */
    private void prepareAlgorithmDependencies() {
        generatePrimes();
        generateModulus();
        generateTotient();
        generatePublicKeyExponent();
        generatePrivateKeyExponent();
    }

    /**
     * Generates the primes
     * p and q
     */
    private void generatePrimes() {
        SecureRandom secureRandom = new SecureRandom();
        p = new BigInteger(bitLength / 2, 100, secureRandom);
        q = new BigInteger(bitLength / 2, 100, secureRandom);
    }

    /**
     * Generates the modulus N:
     * n = p * q
     */
    private void generateModulus() {
        n = p.multiply(q);
    }

    /**
     * Generates the Totient m
     * m = (p - 1) * (q - 1)
     */
    private void generateTotient() {
        m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
    }

    /**
     * Generates the Public Key Exponent
     * 1 < e < m, such that
     * e and m are co-prime
     * e is an odd number
     */
    private void generatePublicKeyExponent() {
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
    }

    /**
     * Generates the Private Key Exponent
     * de ~ 1 ( mod m )
     * de = 1 + k*m
     * where k is any integer
     */
    private void generatePrivateKeyExponent() {
        d = e.modInverse(m);
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              Encryption                                             //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////


    /**
     * Encrypts the given plaintext message
     *
     * @param message the data to be encrypted as String
     * @return CipherText as String
     */
    public synchronized String encrypt(String message) {
        return (new BigInteger(message.getBytes())).modPow(e, n).toString();
    }

    /**
     * Encrypts the given plaintext message
     *
     * @param message the data to be encrypted as BigInteger (message in bytes)
     * @return CipherText as bytes
     */
    public synchronized BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }


    /**
     * Encrypts the given CipherText message
     *
     * @param message           the encrypted CipherText to be decrypted as String
     * @param modulus           n
     * @param publicKeyExponent Public Key (e)
     * @return CipherText as String
     */
    public synchronized String encrypt(String message, String modulus, String publicKeyExponent) {
        e = new BigInteger(publicKeyExponent);
        n = new BigInteger(modulus);
        return (new BigInteger(message.getBytes())).modPow(e, n).toString();
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              Decryption                                             //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////


    /**
     * Decrypts the given CipherText message
     *
     * @param cipherText the encrypted CipherText to be decrypted as String
     * @return Actual Message contained in the CipherText as String
     */
    public synchronized String decrypt(String cipherText) {
        return new String((new BigInteger(cipherText)).modPow(d, n).toByteArray());
    }

    /**
     * Decrypts the given CipherText message
     *
     * @param cipherText the encrypted CipherText to be decrypted as BigInteger (cipherText in bytes)
     * @return Actual Message contained in the CipherText as bytes
     */
    public synchronized BigInteger decrypt(BigInteger cipherText) {
        return cipherText.modPow(d, n);
    }


    /**
     * Decrypts the given CipherText message
     *
     * @param cipherText         the encrypted CipherText to be decrypted as String
     * @param modulus            n
     * @param privateKeyExponent Private Key (d)
     * @return Decrypted Message as String
     */
    public synchronized String decrypt(String cipherText, String modulus, String privateKeyExponent) {
        d = new BigInteger(privateKeyExponent);
        n = new BigInteger(modulus);
        return new String((new BigInteger(cipherText)).modPow(d, n).toByteArray());
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              Getters                                                //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public String getModulus() {
        return String.valueOf(n);
    }

    public BigInteger getM() {
        return m;
    }

    public String getPublicKeyExponent() {
        return String.valueOf(e);
    }

    public String getPrivateKeyExponent() {
        return String.valueOf(d);
    }

    public int getBitLength() {
        return bitLength;
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              Setters                                                //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////


    public void setP(BigInteger p) {
        this.p = p;
    }

    public void setQ(BigInteger q) {
        this.q = q;
    }

    public void setModulus(String n) {
        this.n = new BigInteger(n);
    }

    public void setPublicKeyExponent(String e) {
        this.e = new BigInteger(e);
    }

    public void setPrivateKeyExponent(String d) {
        this.d = new BigInteger(d);
    }

    public void setBitLength(int bitLength) {
        this.bitLength = bitLength;
    }
}
