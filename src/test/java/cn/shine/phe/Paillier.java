package cn.shine.phe;

/*
 * @Project PHE-Maven
 * @Package cn.shine.phe
 * @Class   Paillier
 * @Version 1.0.0
 * @Author  Zhan Shi
 * @Time    2022/5/9 16:22
 * @License MIT
 */

import org.apache.commons.math3.util.FastMath;
import org.jetbrains.annotations.NotNull;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.*;

/**
 * todo Public Class Paillier: Paillier Homomorphic Encryption
 *
 * @author Zhan Shi
 */
public class Paillier {
    /**
     * todo Public Static Class PaillierKeyPair: Paillier Key Pair
     */
    public static class PaillierKeyPair {
        /**
         * publicKey: the public key
         */
        public PaillierPublicKey publicKey;
        /**
         * privateKey: the private key
         */
        public PaillierPrivateKey privateKey;

        /**
         * todo Public Function PaillierKeyPair(PaillierPublicKey, PaillierPrivateKey): Class PaillierKeyPair init
         *
         * @param publicKey  the public key
         * @param privateKey the private key
         */
        public PaillierKeyPair(PaillierPublicKey publicKey, PaillierPrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        /**
         * @param nLength the key pair length
         * @return PaillierKeyPair
         * @see PaillierKeyPair#generate(PaillierPrivateKeyring, Integer)
         */
        public static @NotNull PaillierKeyPair generate(Integer nLength) throws Util.ValueErrorException {
            if (nLength == 0) {
                throw new Util.ValueErrorException("key length should not be zero");
            }

            BigInteger p = null, q = null, n = null;
            Integer nLen = 0;
            while (!nLen.equals(nLength)) {
                p = Util.getPrimeOver(nLength / 2);
                q = p;
                while (q.equals(p)) {
                    q = Util.getPrimeOver(nLength / 2);
                }
                n = p.multiply(q);
                nLen = n.bitLength();
            }
            PaillierPublicKey publicKey = new PaillierPublicKey(n);
            PaillierPrivateKey privateKey = new PaillierPrivateKey(publicKey, p, q);

            return new PaillierKeyPair(publicKey, privateKey);
        }

        /**
         * todo Public Static Function generate(PaillierPrivateKeyring, Integer): generate PHE Key Pair
         *
         * @param privateKeyring the private keyring
         * @param nLength        the key pair length
         * @return PaillierKeyPair
         */
        public static @NotNull PaillierKeyPair generate(@NotNull PaillierPrivateKeyring privateKeyring, Integer nLength) {
            PaillierKeyPair keyPair = generate(nLength);
            privateKeyring.add(keyPair.privateKey);

            return keyPair;
        }
    }

    /**
     * todo Public Static Class PaillierPublicKey: Paillier Public Key
     */
    public static class PaillierPublicKey {
        /**
         * n: the n param of public key
         */
        public BigInteger n;
        /**
         * g:       the g param of public key
         * nSquare: the square of n
         */
        private final BigInteger g, nSquare;
        /**
         * maxInt: the max number of plaintext
         */
        final BigInteger maxInt;

        /**
         * todo Public Function PaillierPublicKey(BigInteger): Class PaillierPublicKey init
         *
         * @param n the n param of public key
         */
        public PaillierPublicKey(@NotNull BigInteger n) {
            this.g = n.add(BigInteger.ONE);
            this.n = n;
            this.nSquare = n.pow(2);
            this.maxInt = n.divide(BigInteger.valueOf(3)).subtract(BigInteger.ONE);
        }

        @Override
        public String toString() {
            return String.format("<PaillierPublicKey %s>", Integer.toHexString(this.hashCode()));
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            PaillierPublicKey publicKey = (PaillierPublicKey) o;

            return n.equals(publicKey.n);
        }

        @Override
        public int hashCode() {
            return Objects.hash(n);
        }

        /**
         * todo Public Function rawEncrypt(Object, Integer): number encryption with obfuscator
         *
         * @param plaintext the number of plaintext
         * @param rValue    obfuscator
         * @return BigInteger
         */
        public @NotNull BigInteger rawEncrypt(Object plaintext, Integer rValue) {
            plaintext = Util.wrapBig(plaintext);
            BigInteger nudeCiphertext = BigInteger.ZERO;

            if (plaintext instanceof BigInteger) {
                BigInteger pBigInteger = (BigInteger) plaintext;

                if (this.n.subtract(this.maxInt).compareTo(pBigInteger) <= 0 && (pBigInteger).compareTo(this.n) < 0) {
                    // very large plaintext, take a sneaky shortcut using inverses
                    BigInteger negPlaintext = this.n.subtract(pBigInteger);
                    // n * plaintext + 1 mod n^2
                    BigInteger negCiphertext = (this.n.multiply(negPlaintext).add(BigInteger.ONE)).mod(this.nSquare);
                    nudeCiphertext = Util.invert(negCiphertext, this.nSquare);
                } else {
                    nudeCiphertext = (this.n.multiply(pBigInteger).add(BigInteger.ONE)).mod(this.nSquare);
                }
            } else if (plaintext instanceof BigDecimal) {
                // see plaintext instanceof BigInteger
                BigDecimal pBigDecimal = (BigDecimal) plaintext;
                BigDecimal nBigDecimal = new BigDecimal(this.n);
                if (nBigDecimal.subtract(new BigDecimal(this.maxInt)).compareTo(pBigDecimal) <= 0 &&
                        pBigDecimal.compareTo(nBigDecimal) < 0) {
                    BigDecimal negPlaintext = nBigDecimal.subtract(pBigDecimal);
                    BigDecimal negCipherBigDecimal = nBigDecimal.multiply(negPlaintext).add(BigDecimal.ONE);
                    BigInteger negCiphertext = negCipherBigDecimal.toBigInteger().mod(this.nSquare);
                    nudeCiphertext = Util.invert(negCiphertext, this.nSquare);
                } else {
                    BigDecimal nudeCipherBigDecimal = nBigDecimal.multiply(pBigDecimal).add(BigDecimal.ONE);
                    nudeCiphertext = nudeCipherBigDecimal.toBigInteger().mod(this.nSquare);
                }
            }

            BigInteger r = rValue == 0 ? BigInteger.ONE : this.getRandomLtN();
            BigInteger obfuscator = r.modPow(this.n, this.nSquare);

            return Util.mulMod(nudeCiphertext, obfuscator, this.nSquare);
        }

        /**
         * todo Public Function getRandomLtN(): get random in (1, public.n)
         *
         * @return BigInteger
         */
        public @NotNull BigInteger getRandomLtN() {
            Random rand = new Random();
            BigInteger result;
            do {
                result = new BigInteger(this.n.bitLength(), rand).abs();
            } while (result.equals(BigInteger.ZERO));

            return result;
        }

        /**
         * @param value number to be encrypted
         * @return EncryptedNumber
         * @see PaillierPublicKey#encrypt(Object, Double, Integer)
         */
        public EncryptedNumber encrypt(Object value) {
            return encrypt(value, null, null);
        }

        /**
         * @param value     number to be encrypted
         * @param precision the precision of encryption
         * @return EncryptedNumber
         * @see PaillierPublicKey#encrypt(Object, Double, Integer)
         */
        public EncryptedNumber encrypt(Object value, Double precision) {
            return encrypt(value, precision, null);
        }

        /**
         * todo Public Function EncryptedNumber encrypt(Object, Double, Integer): plaintext to encrypting
         *
         * @param value     number to be encrypted
         * @param precision the precision of encryption
         * @param rValue    value of obfuscator
         * @return EncryptedNumber
         */
        public EncryptedNumber encrypt(Object value, Double precision, Integer rValue) {
            EncodedNumber encoding;
            value = Util.wrapBig(value);

            if (value instanceof EncodedNumber) {
                encoding = ((EncodedNumber) value);
            } else {
                if (precision == null) {
                    encoding = EncodedNumber.encode(this, value);
                } else {
                    encoding = EncodedNumber.encode(this, value, precision);
                }

            }
            if (rValue == null) {
                return encryptEncoded(encoding);
            } else {
                return encryptEncoded(encoding, rValue);
            }
        }

        /**
         * @param encoding encoded number
         * @return EncryptedNumber
         * @see PaillierPublicKey#encryptEncoded(EncodedNumber, Integer)
         */
        public @NotNull EncryptedNumber encryptEncoded(@NotNull EncodedNumber encoding) {
            Integer rValue = 0;
            EncryptedNumber encryptedNumber = encryptEncoded(encoding, rValue);
            encryptedNumber.obfuscate();

            return encryptedNumber;
        }

        /**
         * todo Public Function encryptEncoded(EncodedNumber): encrypted number encode
         *
         * @param encoding encoded number
         * @param rValue   obfuscator
         * @return EncryptedNumber
         */
        public @NotNull EncryptedNumber encryptEncoded(@NotNull EncodedNumber encoding, Integer rValue) {
            Integer obfuscator = rValue == 0 ? 1 : rValue;
            BigInteger ciphertext = rawEncrypt(encoding.encoding, obfuscator);

            return new EncryptedNumber(this, ciphertext, encoding.exponent);
        }
    }

    /**
     * todo Public Static Class PaillierPrivateKey: Paillier Private Key
     */
    public static class PaillierPrivateKey {
        /**
         * publicKey: the public key of the private key
         */
        public PaillierPublicKey publicKey;
        /**
         * p: the p param of private key
         * q: the q param of private key
         */
        public BigInteger p, q;
        /**
         * pSquare:   the square of p
         * qSquare:   the square of q
         * pInverse:  the inverse of p
         * hp:        hFunction h(p)
         * hq:        hFunction h(q)
         */
        private final BigInteger pSquare, qSquare, pInverse, hp, hq;

        /**
         * todo Public Function PaillierPrivateKey(PaillierPublicKey, BigInteger, BigInteger): Class PaillierPrivateKey init
         *
         * @param publicKey the public key of the private key
         * @param p         the p param of private key
         * @param q         the q param of private key
         * @throws Util.ValueErrorException if the public key and the private key is not match, or p is equal q
         */
        public PaillierPrivateKey(@NotNull PaillierPublicKey publicKey, @NotNull BigInteger p, BigInteger q)
                throws Util.ValueErrorException {
            if (!p.multiply(q).equals(publicKey.n)) {
                throw new Util.ValueErrorException("given public key does not match the given p and q");
            }

            if (p.equals(q)) {
                throw new Util.ValueErrorException("p and q have to be different");
            }

            this.publicKey = publicKey;

            if (q.compareTo(p) < 0) {
                this.p = q;
                this.q = p;
            } else {
                this.p = p;
                this.q = q;
            }

            this.pSquare = this.p.pow(2);
            this.qSquare = this.q.pow(2);
            this.pInverse = Util.invert(this.p, this.q);

            this.hp = hFunction(this.p, this.pSquare);
            this.hq = hFunction(this.q, this.qSquare);
        }

        @Override
        public String toString() {
            return String.format("<PaillierPrivateKey for %s>", this.publicKey.toString());
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof PaillierPrivateKey)) {
                return false;
            }
            PaillierPrivateKey that = (PaillierPrivateKey) o;

            return p.equals(that.p) && q.equals(that.q);
        }

        @Override
        public int hashCode() {
            return Objects.hash(p, q);
        }

        /**
         * todo Public Function fromTotient(PaillierPublicKey, BigInteger): given the totient, one can factorize the modulus
         *
         * @param publicKey public key
         * @param totient   the totient of the modulus (p - 1) * (q - 1)
         * @return PaillierPrivateKey
         * @throws Util.ValueErrorException if p * q != publicKey.n
         */
        public PaillierPrivateKey fromTotient(@NotNull PaillierPublicKey publicKey, BigInteger totient)
                throws Util.ValueErrorException {
            BigInteger pPlusQ = publicKey.n.subtract(totient).subtract(BigInteger.ONE);
            BigInteger pMinusQ = pPlusQ.pow(2).subtract(publicKey.n.multiply(BigInteger.valueOf(4))).sqrt();
            BigInteger q = (pPlusQ.subtract(pMinusQ)).divide(BigInteger.TWO);
            BigInteger p = pPlusQ.subtract(q);
            if (!p.multiply(q).equals(publicKey.n)) {
                throw new Util.ValueErrorException("given public key and totient do not match");
            }

            return new PaillierPrivateKey(publicKey, p, q);
        }

        /**
         * todo Public Function decrypt(EncryptedNumber): encrypted number to decrypting
         *
         * @param encryptedNumber the encrypted number
         * @return Object -> BigInteger or BigDecimal
         */
        public Object decrypt(EncryptedNumber encryptedNumber) {
            EncodedNumber encoded = decryptEncoded(encryptedNumber);

            return encoded.decode();
        }

        /**
         * todo Public Function decryptEncoded(EncryptedNumber): decrypted number decode
         *
         * @param encryptedNumber the encrypted number
         * @return EncodedNumber
         * @throws Util.ValueErrorException if public keys are not match
         */
        public @NotNull EncodedNumber decryptEncoded(@NotNull EncryptedNumber encryptedNumber)
                throws Util.ValueErrorException {
            if (this.publicKey != encryptedNumber.publicKey) {
                throw new Util.ValueErrorException("encrypted_number was encrypted against a different key");
            }

            boolean beSecure = false;
            BigInteger encoded = rawDecrypt(encryptedNumber.ciphertext(beSecure));
            return new EncodedNumber(this.publicKey, encoded, encryptedNumber.exponent);
        }

        /**
         * todo Public Function rawDecrypt(BigInteger): number decryption with obfuscator
         *
         * @param ciphertext the ciphertext
         * @return BigInteger
         */
        public @NotNull BigInteger rawDecrypt(@NotNull BigInteger ciphertext) {
            BigInteger lFuncP = lFunction(ciphertext.modPow(this.p.subtract(BigInteger.ONE), this.pSquare), this.p);
            BigInteger decryptToP = Util.mulMod(lFuncP, this.hp, this.p);

            BigInteger lFuncQ = lFunction(ciphertext.modPow(this.q.subtract(BigInteger.ONE), this.qSquare), this.q);
            BigInteger decryptToQ = Util.mulMod(lFuncQ, this.hq, this.q);

            return crt(decryptToP, decryptToQ);
        }


        /**
         * todo Public Function hFunction(BigInteger, BigInteger): Decryption using Chinese-remaindering
         *
         * @param x       a param x
         * @param xSquare the square of x
         * @return BigInteger
         */
        public @NotNull BigInteger hFunction(BigInteger x, BigInteger xSquare) {
            return Util.invert(lFunction(this.publicKey.g.modPow(x.subtract(BigInteger.ONE), xSquare), x), x);
        }

        /**
         * todo Public Function lFunction(BigInteger, BigInteger): l function of Paillier's paper
         *
         * @param x a param x
         * @param p a param p
         * @return BigInteger L(x,p) = (x-1)/p
         */
        public @NotNull BigInteger lFunction(@NotNull BigInteger x, BigInteger p) {
            return (x.subtract(BigInteger.ONE)).divide(p);
        }

        /**
         * todo Public Function crt(BigInteger, BigInteger): the Chinese Remainder Theorem as needed for decryption
         *
         * @param mp the solution modulo p
         * @param mq the solution modulo q
         * @return BigInteger the solution modulo n=pq
         */
        public @NotNull BigInteger crt(BigInteger mp, @NotNull BigInteger mq) {
            BigInteger u = Util.mulMod(mq.subtract(mp), this.pInverse, this.q);

            return mp.add(u.multiply(this.p));
        }
    }

    /**
     * todo Public Static Class PaillierPrivateKeyring: Paillier Private Keyring
     */
    public static class PaillierPrivateKeyring {
        /**
         * keyring: the private keyring
         */
        public HashMap<PaillierPublicKey, PaillierPrivateKey> keyring = new HashMap<>();

        /**
         * @see PaillierPrivateKeyring#PaillierPrivateKeyring(ArrayList)
         */
        public PaillierPrivateKeyring() {

        }

        /**
         * todo Public Function PaillierPrivateKeyring(ArrayList): Class PaillierPrivateKeyring init
         *
         * @param privateKeys the private keys
         */
        public PaillierPrivateKeyring(@NotNull ArrayList<PaillierPrivateKey> privateKeys) {
            for (PaillierPrivateKey privateKey : privateKeys) {
                this.keyring.put(privateKey.publicKey, privateKey);
            }
        }

        /**
         * todo Public Function get(PaillierPublicKey): get private key corresponding to public key
         *
         * @param key the public key
         * @return PaillierPrivateKey
         */
        public PaillierPrivateKey get(PaillierPublicKey key) {
            return this.keyring.get(key);
        }

        /**
         * todo Public Function size(): get length of private keyring
         *
         * @return Integer
         */
        public Integer size() {
            return this.keyring.size();
        }

        /**
         * todo Public Function iter(): wrap private keyring into an iterator
         *
         * @return Iterator
         */
        public Iterator<PaillierPublicKey> iter() {
            return this.keyring.keySet().iterator();
        }

        /**
         * todo Public Function del(PaillierPublicKey): delete public key and private key of private keyring
         *
         * @param key the public key
         */
        public void del(PaillierPublicKey key) {
            this.keyring.remove(key);
        }

        /**
         * todo Public Function add(PaillierPrivateKey): add public key and private key into private keyring
         *
         * @param privateKey the private key
         */
        public void add(PaillierPrivateKey privateKey) {
            this.keyring.put(privateKey.publicKey, privateKey);
        }

        /**
         * todo Public Function decrypt(EncryptedNumber): decrypted ciphertext using private keyring
         *
         * @param encryptedNumber the encrypted number
         * @return Object -> BigInteger and BigDecimal
         */
        public Object decrypt(@NotNull EncryptedNumber encryptedNumber) {
            PaillierPrivateKey relevantPrivateKey = this.keyring.get(encryptedNumber.publicKey);

            return relevantPrivateKey.decrypt(encryptedNumber);
        }
    }

    /**
     * todo Public Static Class EncryptedNumber: Encrypted number
     */
    public static class EncryptedNumber {
        /**
         * publicKey: the public key of the encrypted number
         */
        public PaillierPublicKey publicKey;
        /**
         * exponent: the exponent of the encrypted number
         */
        public BigInteger exponent;
        /**
         * ciphertext: the ciphertext of the encrypted number
         */
        private BigInteger ciphertext;
        /**
         * isObfuscated: the encrypted number is confused or not
         */
        private boolean isObfuscated;

        /**
         * @param publicKey  the public key of the encrypted number
         * @param ciphertext the ciphertext of the encrypted number
         * @see EncodedNumber#EncodedNumber(PaillierPublicKey, BigInteger, BigInteger)
         */
        public EncryptedNumber(PaillierPublicKey publicKey, BigInteger ciphertext) {
            new EncryptedNumber(publicKey, ciphertext, BigInteger.ZERO);
        }

        /**
         * todo Public Function EncryptedNumber(PaillierPublicKey, BigInteger, BigInteger): Class EncryptedNumber init
         *
         * @param publicKey  the public key of the encrypted number
         * @param ciphertext the ciphertext of the encrypted number
         * @param exponent   the exponent of the encrypted number
         */
        public EncryptedNumber(PaillierPublicKey publicKey, BigInteger ciphertext, BigInteger exponent) {
            this.publicKey = publicKey;
            this.ciphertext = ciphertext;
            this.exponent = exponent;
            this.isObfuscated = false;
        }

        /**
         * todo Public Function add(Object): add an int, float, EncryptedNumber or EncodedNumber
         *
         * @param other other number -> int, float, EncryptedNumber or EncodedNumber
         * @return EncryptedNumber this + other
         * @throws Util.ValueErrorException if public key is not match
         */
        public EncryptedNumber add(Object other) throws Util.ValueErrorException {
            if (other instanceof EncryptedNumber) {
                return addEncrypted((EncryptedNumber) other);
            } else if (other instanceof EncodedNumber) {
                return addEncoded((EncodedNumber) other);
            } else {
                other = Util.wrapBig(other);
                return addScalar(other);
            }
        }

        /**
         * todo Public Function multiply(Object): multiply an int, float or EncodedNumber
         *
         * @param other other number -> int, float or EncodedNumber
         * @return EncryptedNumber this * other
         * @throws Util.NotImplementedErrorException if other is EncryptedNumber
         */
        public EncryptedNumber multiply(Object other) throws Util.NotImplementedErrorException {
            EncodedNumber encoding;

            if (other instanceof EncryptedNumber) {
                throw new Util.NotImplementedErrorException("good luck with that...");
            } else if (other instanceof EncodedNumber) {
                encoding = (EncodedNumber) other;
            } else {
                other = Util.wrapBig(other);
                encoding = EncodedNumber.encode(this.publicKey, other);
            }

            BigInteger product = rawMul(encoding.encoding);
            BigInteger exponent = this.exponent.add(encoding.exponent);

            return new EncryptedNumber(this.publicKey, product, exponent);
        }

        /**
         * todo Public Function subtract(Object): subtract an int, float, EncryptedNumber or EncodedNumber
         *
         * @param other other number -> int, float, EncryptedNumber or EncodedNumber
         * @return EncryptedNumber this - other
         * @throws Util.ValueErrorException if public key is not match
         */
        public EncryptedNumber subtract(Object other) throws Util.ValueErrorException {
            if (other instanceof EncryptedNumber) {
                return this.add(((EncryptedNumber) other).multiply(-1));
            } else if (other instanceof EncodedNumber) {
                EncryptedNumber encryptedNumber = this.publicKey.encrypt(other);

                return this.add(encryptedNumber.multiply(-1));
            } else {
                other = Util.wrapBig(other);
                if (other instanceof BigInteger) {
                    return this.add(((BigInteger) other).multiply(BigInteger.valueOf(-1)));
                } else {
                    return this.add(((BigDecimal) other).multiply(BigDecimal.valueOf(-1)));
                }
            }
        }

        /**
         * todo Public Function divide(Object): divide an int or float
         *
         * @param other other number -> int, float
         * @return EncryptedNumber this / other
         * @throws Util.NotImplementedErrorException should not be EncryptedNumber
         * @throws Util.TypeErrorException           should not be EncodedNumber
         */
        public EncryptedNumber divide(Object other) throws Util.NotImplementedErrorException, Util.TypeErrorException {
            if (other instanceof EncryptedNumber) {
                throw new Util.NotImplementedErrorException("good luck with that...");
            } else if (other instanceof EncodedNumber) {
                throw new Util.TypeErrorException("should not be EncodedNumber");
            } else {
                other = Util.wrapBig(other);
                if (other instanceof BigInteger) {
                    return this.multiply(BigDecimal.valueOf(1 / ((BigInteger) other).doubleValue()));
                } else {
                    return this.multiply(BigDecimal.valueOf(1 / ((BigDecimal) other).doubleValue()));
                }
            }
        }

        /**
         * todo Public Function ciphertext(boolean): set the obfuscated of the ciphertext
         *
         * @param beSecure is obfuscated or not
         * @return BigInteger
         */
        public BigInteger ciphertext(boolean beSecure) {
            if (beSecure && !this.isObfuscated) {
                this.obfuscate();
            }
            return this.ciphertext;
        }

        /**
         * todo Public Function decreaseExponentTo(BigInteger): decrease exponent
         *
         * @param newExp new exponent
         * @return EncryptedNumber
         * @throws Util.ValueErrorException if newExp > this.exponent
         */
        public EncryptedNumber decreaseExponentTo(@NotNull BigInteger newExp) throws Util.ValueErrorException {
            if (newExp.compareTo(this.exponent) > 0) {
                String exception = "New exponent %s should be more negative than old exponent %s";
                throw new Util.ValueErrorException(String.format(exception, newExp, this.exponent));
            }
            double baseExp = FastMath.pow(EncodedNumber.BASE, this.exponent.subtract(newExp).intValue());
            EncryptedNumber multiplied = this.multiply(new BigDecimal(Double.toString(baseExp)));
            multiplied.exponent = newExp;

            return multiplied;
        }

        /**
         * todo Public Function obfuscate(): the obfuscate function
         */
        public void obfuscate() {
            BigInteger r = this.publicKey.getRandomLtN();
            BigInteger rPowN = r.modPow(this.publicKey.n, this.publicKey.nSquare);
            this.ciphertext = this.ciphertext.multiply(rPowN).mod(this.publicKey.nSquare);
            this.isObfuscated = true;
        }

        /**
         * todo Private Function addScalar(Object): add int or float
         *
         * @param scalar BigInteger or BigDecimal
         * @return EncryptedNumber
         * @throws Util.ValueErrorException if public key is not match
         */
        private @NotNull EncryptedNumber addScalar(Object scalar) throws Util.ValueErrorException {
            scalar = Util.wrapBig(scalar);
            EncodedNumber encoded = EncodedNumber.encode(this.publicKey, scalar, null, this.exponent.intValue());
            return addEncoded(encoded);
        }

        /**
         * todo Private Function addEncoded(EncodedNumber): add EncodedNumber
         *
         * @param encoded EncodedNumber
         * @return EncryptedNumber
         * @throws Util.ValueErrorException if public key is not match
         */
        private @NotNull EncryptedNumber addEncoded(@NotNull EncodedNumber encoded) throws Util.ValueErrorException {
            if (this.publicKey != encoded.publicKey) {
                throw new Util.ValueErrorException("Attempted to add numbers encoded against different public keys");
            }
            // to add two numbers, their exponents must match
            EncryptedNumber a = this;
            EncodedNumber b = encoded;
            if (a.exponent.compareTo(b.exponent) > 0) {
                a = decreaseExponentTo(b.exponent);
            } else if (a.exponent.compareTo(b.exponent) < 0) {
                b = b.decreaseExponentTo(a.exponent);
            }

            BigInteger encryptedScalar = a.publicKey.rawEncrypt(b.encoding, 1);
            boolean beSecure = false;
            BigInteger sumCiphertext = a.rawAdd(a.ciphertext(beSecure), encryptedScalar);

            return new EncryptedNumber(a.publicKey, sumCiphertext, a.exponent);
        }

        /**
         * todo Private Function addEncrypted(EncryptedNumber): add EncryptedNumber
         *
         * @param other EncryptedNumber
         * @return EncryptedNumber
         * @throws Util.ValueErrorException if public key is not match
         */
        private @NotNull EncryptedNumber addEncrypted(@NotNull EncryptedNumber other) throws Util.ValueErrorException {
            if (this.publicKey != other.publicKey) {
                throw new Util.ValueErrorException("Attempted to add numbers encoded against different public keys");
            }
            EncryptedNumber a = this;
            EncryptedNumber b = other;

            if (a.exponent.compareTo(b.exponent) > 0) {
                a = this.decreaseExponentTo(b.exponent);
            } else if (a.exponent.compareTo(b.exponent) < 0) {
                b = b.decreaseExponentTo(a.exponent);
            }

            boolean beSecure = false;
            BigInteger sumCiphertext = a.rawAdd(a.ciphertext(beSecure), b.ciphertext(beSecure));

            return new EncryptedNumber(a.publicKey, sumCiphertext, a.exponent);
        }

        /**
         * todo Private Function rawAdd(BigInteger, BigInteger): E(a + b)
         *
         * @param a ciphertext a
         * @param b ciphertext b
         * @return BigInteger E(a + b)
         */
        private @NotNull BigInteger rawAdd(BigInteger a, BigInteger b) {
            return Util.mulMod(a, b, this.publicKey.nSquare);
        }

        /**
         * todo Private Function rawMul(BigInteger): E(a) * b
         *
         * @param plaintext plaintext
         * @return BigInteger E(a) * b
         */
        private @NotNull BigInteger rawMul(@NotNull BigInteger plaintext) {
            if (plaintext.compareTo(BigInteger.ZERO) < 0 || plaintext.compareTo(this.publicKey.n) >= 0) {
                throw new Util.ValueErrorException(String.format("Scalar out of bounds: %s", plaintext));
            }

            boolean beSecure = false;
            if (this.publicKey.n.subtract(this.publicKey.maxInt).compareTo(plaintext) <= 0) {
                BigInteger negC = Util.invert(this.ciphertext(beSecure), this.publicKey.nSquare);
                BigInteger negScalar = this.publicKey.n.subtract(plaintext);

                return negC.modPow(negScalar, this.publicKey.nSquare);
            } else {
                return this.ciphertext(beSecure).modPow(plaintext, this.publicKey.nSquare);
            }
        }
    }
}
