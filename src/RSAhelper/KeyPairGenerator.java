package RSAhelper;

import java.math.BigInteger;
import java.security.SecureRandom;

public class KeyPairGenerator {

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
    public KeyPairGenerator() {
        //Default Bit Length
        this(512);
    }

    /**
     * Overload Constructor
     *
     * @param bitLength user specified computation bitlength
     */
    public KeyPairGenerator(int bitLength) {
        this.bitLength = bitLength;

        //Default start value for public key exponent
        this.e = new BigInteger(String.valueOf(Math.toIntExact((long) (Math.pow(2, 16) + 1))));

        prepareAlgorithmDependencies();
    }

    /**
     * Overload Constructor
     *
     * @param bitLength                 user specified computation bitlength
     * @param publicKeyExponentMinValue minimum exponent number
     */
    public KeyPairGenerator(int bitLength, int publicKeyExponentMinValue) {
        this.bitLength = bitLength;
        this.e = new BigInteger(String.valueOf(publicKeyExponentMinValue));

        prepareAlgorithmDependencies();
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
    //                                              Getters                                                //
    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    public String getModulus() {
        return String.valueOf(n);
    }

    public String getPublicKeyExponent() {
        return String.valueOf(e);
    }

    public String getPrivateKeyExponent() {
        return String.valueOf(d);
    }
}
