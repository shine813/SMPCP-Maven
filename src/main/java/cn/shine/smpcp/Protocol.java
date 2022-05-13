package cn.shine.smpcp;

/*
 * @Project SMPCP-Maven
 * @Package cn.shine.smpcp
 * @Class   Protocol
 * @Version 1.0.0
 * @Author  Zhan Shi
 * @Time    2022/5/12 22:51
 * @License MIT
 */

import cn.shine.phe.Paillier.EncryptedNumber;
import cn.shine.phe.Paillier.PaillierPrivateKey;
import cn.shine.phe.Paillier.PaillierPublicKey;
import org.jetbrains.annotations.NotNull;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;
import java.util.Random;

/**
 * todo Public Class Protocol: Protocol
 *
 * @author Zhan Shi
 */
public class Protocol {
    /**
     * todo Public Static Class SMPCProtocol: Secure Multi-party Computation Protocol
     */
    public static class SMPCProtocol {
        /**
         * c1: cloud platform
         * c2: third cloud platform
         */
        final CloudPlatform c1;
        final CloudPlatformThird c2;
        /**
         * cipher: ciphertext
         */
        EncryptedNumber cipher;

        /**
         * todo Public Function SMPCProtocol(CloudPlatform, CloudPlatformThird): Protocol Init
         *
         * @param c1 cloud platform
         * @param c2 third cloud platform
         */
        public SMPCProtocol(CloudPlatform c1, CloudPlatformThird c2) {
            this.c1 = c1;
            this.c2 = c2;
        }

        /**
         * @param cipher cipher: ciphertext
         * @see SMPCProtocol#SMPCProtocol(CloudPlatform, CloudPlatformThird)
         */
        public SMPCProtocol(CloudPlatform c1, CloudPlatformThird c2, EncryptedNumber cipher) {
            this.c1 = c1;
            this.c2 = c2;
            this.cipher = cipher;
        }

        /**
         * todo Public Function encode(EncryptedNumber): encode encrypted number
         *
         * @param encryptedNumber encrypted number
         * @return SecureMultiPartyComputationProtocol
         */
        public SMPCProtocol encode(EncryptedNumber encryptedNumber) {
            return new SMPCProtocol(this.c1, this.c2, encryptedNumber);
        }

        /**
         * todo Public Function decode(): decode encrypted number
         *
         * @return EncryptedNumber
         */
        public EncryptedNumber decode() {
            return this.cipher;
        }

        /**
         * todo Public Function multiply(EncryptedNumber): secure multiply protocol
         *
         * @param other other encrypted number
         * @return EncryptedNumber
         */
        public EncryptedNumber multiply(EncryptedNumber other) {
            return this.c1.multiply(this.cipher, other, this.c2);
        }

        /**
         * todo Public Function divide(EncryptedNumber): secure division protocol
         *
         * @param other other encrypted number
         * @return EncryptedNumber
         */
        public EncryptedNumber divide(EncryptedNumber other) {
            return this.c1.divide(this.cipher, other, this.c2);
        }

        /**
         * todo Public Function optimum(EncryptedNumber, String mode): secure optimum protocol
         *
         * @param other other encrypted number
         * @param mode  optimum mode 'max' or 'min'
         * @return EncryptedNumber
         */
        public EncryptedNumber optimum(EncryptedNumber other, String mode) {
            return this.c1.optimum(this.cipher, other, this.c2, mode);
        }

        /**
         * todo Public Function parity(EncryptedNumber): secure parity protocol
         *
         * @return EncryptedNumber odd number -> E(1); even number -> E(0)
         */
        public EncryptedNumber parity() {
            return this.c1.parity(this.cipher, this.c2);
        }

        /**
         * todo Public Function bitAnd(EncryptedNumber): secure bit and protocol
         *
         * @param other other encrypted number
         * @return EncryptedNumber
         */
        public EncryptedNumber bitAnd(EncryptedNumber other) {
            return this.c1.bitAnd(this.cipher, other, this.c2);
        }

        /**
         * todo Public Function bitOr(EncryptedNumber): secure bit or protocol
         *
         * @param other other encrypted number
         * @return EncryptedNumber
         */
        public EncryptedNumber bitOr(EncryptedNumber other) {
            return this.c1.bitOr(this.cipher, other, this.c2);
        }

        /**
         * todo Public Function bitNot(EncryptedNumber): secure bit not protocol
         *
         * @return EncryptedNumber
         */
        public EncryptedNumber bitNot() {
            return this.c1.bitNot(this.cipher);
        }

        /**
         * todo Public Function bitXor(EncryptedNumber): secure bit xor protocol
         *
         * @param other other encrypted number
         * @return EncryptedNumber
         */
        public EncryptedNumber bitXor(EncryptedNumber other) {
            return this.c1.bitXor(this.cipher, other, this.c2);
        }

        /**
         * todo Public Function equals(EncryptedNumber): secure equals protocol
         *
         * @param other other encrypted number
         * @return EncryptedNumber
         */
        public EncryptedNumber equals(EncryptedNumber other) {
            return this.c1.equals(this.cipher, other, this.c2);
        }

        /**
         * todo Public Function notEquals(EncryptedNumber): secure not equals protocol
         *
         * @param other other encrypted number
         * @return EncryptedNumber
         */
        public EncryptedNumber notEquals(EncryptedNumber other) {
            return this.c1.notEquals(this.cipher, other, this.c2);
        }

        /**
         * todo Public Function greaterThan(EncryptedNumber): secure greater than protocol
         *
         * @param other other encrypted number
         * @return EncryptedNumber
         */
        public EncryptedNumber greaterThan(EncryptedNumber other) {
            return this.c1.greaterThan(this.cipher, other, this.c2);
        }

        /**
         * todo Public Function greaterEquals(EncryptedNumber): secure greater equals protocol
         *
         * @param other other encrypted number
         * @return EncryptedNumber
         */
        public EncryptedNumber greaterEquals(EncryptedNumber other) {
            return this.c1.greaterEquals(this.cipher, other, this.c2);
        }

        /**
         * todo Public Function lessThan(EncryptedNumber): secure less than protocol
         *
         * @param other other encrypted number
         * @return EncryptedNumber
         */
        public EncryptedNumber lessThan(EncryptedNumber other) {
            return this.c1.lessThan(this.cipher, other, this.c2);
        }

        /**
         * todo Public Function lessEquals(EncryptedNumber): secure less equals protocol
         *
         * @param other other encrypted number
         * @return EncryptedNumber
         */
        public EncryptedNumber lessEquals(EncryptedNumber other) {
            return this.c1.lessEquals(this.cipher, other, this.c2);
        }
    }

    /**
     * todo Public Static Class CloudPlatform: Cloud Platform Class
     */
    public static class CloudPlatform {

        /**
         * publicKey: public key
         */
        final PaillierPublicKey publicKey;
        /**
         * keyLength: keypair length
         */
        final Integer keyLength;
        /**
         * eOne: encrypted number 1
         */
        final EncryptedNumber eOne;

        /**
         * todo Public Function CloudPlatform(PaillierPublicKey): Class CloudPlatform Init
         *
         * @param publicKey public key
         */
        public CloudPlatform(PaillierPublicKey publicKey) {
            this.publicKey = publicKey;
            this.keyLength = this.publicKey.n.bitLength();
            this.eOne = this.publicKey.encrypt(1);
        }

        /**
         * todo Public Function multiply(EncryptedNumber, EncryptedNumber, CloudPlatformThird): secure multiply protocol
         *
         * @param cipher cipher 1
         * @param other  cipher 2
         * @param c2     third cloud platform
         * @return EncryptedNumber
         */
        public EncryptedNumber multiply(@NotNull EncryptedNumber cipher, @NotNull EncryptedNumber other, @NotNull CloudPlatformThird c2) {
            BigInteger r1 = getRandomLtN();
            BigInteger r2 = getRandomLtN();

            EncryptedNumber h1 = cipher.add(r1);
            EncryptedNumber h2 = other.add(r2);

            return c2.multiply(h1, h2).subtract(cipher.multiply(r2).add(other.multiply(r1)).add(r1.multiply(r2)));
        }

        /**
         * todo Public Function divide(EncryptedNumber, EncryptedNumber, CloudPlatformThird): secure divide protocol
         *
         * @param cipher cipher 1
         * @param other  cipher 2
         * @param c2     third cloud platform
         * @return EncryptedNumber
         */
        public EncryptedNumber divide(@NotNull EncryptedNumber cipher, @NotNull EncryptedNumber other, @NotNull CloudPlatformThird c2) {
            BigInteger r1 = getRandomLtN();
            BigInteger r2 = getRandomLtN();

            EncryptedNumber h1 = cipher.multiply(r1).add(other.multiply(r1).multiply(r2));
            EncryptedNumber h2 = other.multiply(r1);

            return c2.divide(h1, h2).subtract(r2);
        }

        /**
         * todo Public Function optimum(EncryptedNumber, EncryptedNumber, CloudPlatformThird): secure optimum protocol
         *
         * @param cipher cipher 1
         * @param other  cipher 2
         * @param c2     third cloud platform
         * @param mode   optimum mode 'max' or 'min'
         * @return EncryptedNumber
         */
        public EncryptedNumber optimum(EncryptedNumber cipher, EncryptedNumber other, CloudPlatformThird c2, String mode) {
            BigInteger r1 = getRandomLtN();
            BigInteger r2 = getRandomLtN();
            BigInteger r3 = getRandomLtN();

            EncryptedNumber h1, h2, h3;
            double v = 5e-1;
            if (new Random().nextDouble() > v) {
                h1 = (cipher.subtract(other)).multiply(r1);
                h2 = cipher.add(r2);
                h3 = other.add(r3);
            } else {
                h1 = (other.subtract(cipher)).multiply(r1);
                h2 = other.add(r2);
                h3 = cipher.add(r3);
            }

            ArrayList<EncryptedNumber> param = c2.optimum(h1, h2, h3, mode);
            EncryptedNumber alpha = param.get(0);
            EncryptedNumber beta = param.get(1);

            return cipher.add(other).subtract(beta).add(alpha.multiply(r3)).add((this.eOne.subtract(alpha)).multiply(r2));
        }

        /**
         * todo Public Function parity(EncryptedNumber, CloudPlatformThird): secure parity protocol
         *
         * @param cipher cipher
         * @param c2     third cloud platform
         * @return EncryptedNumber
         */
        public EncryptedNumber parity(@NotNull EncryptedNumber cipher, @NotNull CloudPlatformThird c2) {
            BigInteger r = getRandomLtN();

            EncryptedNumber h = cipher.add(r);

            EncryptedNumber alpha = c2.parity(h);

            return r.mod(BigInteger.TWO).equals(BigInteger.ZERO) ? alpha : this.eOne.subtract(alpha);
        }

        /**
         * todo Public Function bitAnd(EncryptedNumber, Integer, CloudPlatformThird): secure bit and protocol
         *
         * @param cipher cipher 1
         * @param other  cipher 2
         * @param c2     third cloud platform
         * @return EncryptedNumber
         */
        public EncryptedNumber bitAnd(EncryptedNumber cipher, EncryptedNumber other, CloudPlatformThird c2) {
            return multiply(cipher, other, c2);
        }

        /**
         * todo Public Function bitOr(EncryptedNumber, Integer, CloudPlatformThird): secure bit or protocol
         *
         * @param cipher cipher 1
         * @param other  cipher 2
         * @param c2     third cloud platform
         * @return EncryptedNumber
         */
        public EncryptedNumber bitOr(@NotNull EncryptedNumber cipher, EncryptedNumber other, CloudPlatformThird c2) {
            return cipher.add(other).subtract(bitAnd(cipher, other, c2));
        }

        /**
         * todo Public Static Function bitNot(EncryptedNumber, Integer, CloudPlatformThird): secure bit not protocol
         *
         * @param cipher cipher 1
         * @return EncryptedNumber
         */
        public EncryptedNumber bitNot(EncryptedNumber cipher) {
            return this.eOne.subtract(cipher);
        }

        /**
         * todo Public Static Function bitXor(EncryptedNumber, Integer, CloudPlatformThird): secure bit xor protocol
         *
         * @param cipher cipher 1
         * @param other  cipher 2
         * @param c2     third cloud platform
         * @return EncryptedNumber
         */
        public EncryptedNumber bitXor(@NotNull EncryptedNumber cipher, EncryptedNumber other, CloudPlatformThird c2) {
            return cipher.add(other).subtract(multiply(cipher, other, c2).multiply(2));
        }

        /**
         * todo Public Static Function equals(EncryptedNumber, Integer, CloudPlatformThird): secure equals protocol
         *
         * @param cipher cipher 1
         * @param other  cipher 2
         * @param c2     third cloud platform
         * @return EncryptedNumber
         */
        public EncryptedNumber equals(EncryptedNumber cipher, EncryptedNumber other, CloudPlatformThird c2) {
            BigInteger sigma = BigInteger.valueOf(new Random().nextDouble() > 5e-1 ? -1 : 1);

            BigInteger r1 = getRandomLtN();
            BigInteger r2 = getRandomLtN();

            if (r2.compareTo(r1) > 0) {
                BigInteger tmp = r2;
                r2 = r1;
                r1 = tmp;
            }

            EncryptedNumber r1s = this.publicKey.encrypt(r1.multiply(sigma));
            EncryptedNumber r2o = this.publicKey.encrypt(r2.multiply(sigma));

            EncryptedNumber alpha = multiply(r1s,
                    multiply(cipher.subtract(other), cipher.subtract(other), c2), c2).subtract(r2o);

            return sigma.equals(BigInteger.ONE) ? this.eOne.subtract(c2.equals(alpha)) : c2.equals(alpha);
        }

        /**
         * todo Public Static Function notEquals(EncryptedNumber, Integer, CloudPlatformThird): secure not equals protocol
         *
         * @param cipher cipher 1
         * @param other  cipher 2
         * @param c2     third cloud platform
         * @return EncryptedNumber
         */
        public EncryptedNumber notEquals(EncryptedNumber cipher, EncryptedNumber other, CloudPlatformThird c2) {
            return this.eOne.subtract(equals(cipher, other, c2));
        }

        /**
         * todo Public Static Function greaterThan(EncryptedNumber, Integer, CloudPlatformThird): secure greater than protocol
         *
         * @param cipher cipher 1
         * @param other  cipher 2
         * @param c2     third cloud platform
         * @return EncryptedNumber
         */
        public EncryptedNumber greaterThan(EncryptedNumber cipher, EncryptedNumber other, CloudPlatformThird c2) {
            return getThanParam(other, cipher, c2);
        }

        /**
         * todo Public Static Function greaterEquals(EncryptedNumber, Integer, CloudPlatformThird): secure greater equals protocol
         *
         * @param cipher cipher 1
         * @param other  cipher 2
         * @param c2     third cloud platform
         * @return EncryptedNumber
         */
        public EncryptedNumber greaterEquals(EncryptedNumber cipher, EncryptedNumber other, CloudPlatformThird c2) {
            return bitOr(equals(cipher, other, c2), greaterThan(cipher, other, c2), c2);
        }

        /**
         * todo Public Static Function lessThan(EncryptedNumber, Integer, CloudPlatformThird): secure less than protocol
         *
         * @param cipher cipher 1
         * @param other  cipher 2
         * @param c2     third cloud platform
         * @return EncryptedNumber
         */
        public EncryptedNumber lessThan(EncryptedNumber cipher, EncryptedNumber other, CloudPlatformThird c2) {
            return getThanParam(cipher, other, c2);
        }

        /**
         * @param cipher cipher 1
         * @param other  cipher 2
         * @param c2     third cloud platform
         * @return EncryptedNumber
         * @see CloudPlatform#greaterThan(EncryptedNumber, EncryptedNumber, CloudPlatformThird)
         * @see CloudPlatform#lessThan(EncryptedNumber, EncryptedNumber, CloudPlatformThird)
         */
        private EncryptedNumber getThanParam(EncryptedNumber cipher, EncryptedNumber other, CloudPlatformThird c2) {
            BigInteger sigma = BigInteger.valueOf(new Random().nextDouble() > 5e-1 ? -1 : 1);

            BigInteger r1 = getRandomLtN();
            BigInteger r2 = getRandomLtN();

            if (r2.compareTo(r1) > 0) {
                BigInteger tmp = r2;
                r2 = r1;
                r1 = tmp;
            }

            EncryptedNumber r1s = this.publicKey.encrypt(r1.multiply(sigma));
            EncryptedNumber r2o = this.publicKey.encrypt(r2.multiply(sigma));
            EncryptedNumber alpha = multiply(r1s, cipher.subtract(other), c2).add(r2o);

            return sigma.equals(BigInteger.ONE) ? this.eOne.subtract(c2.equals(alpha)) : c2.equals(alpha);
        }

        /**
         * todo Public Static Function lessEquals(EncryptedNumber, Integer, CloudPlatformThird): secure less equals protocol
         *
         * @param cipher cipher 1
         * @param other  cipher 2
         * @param c2     third cloud platform
         * @return EncryptedNumber
         */
        public EncryptedNumber lessEquals(EncryptedNumber cipher, EncryptedNumber other, CloudPlatformThird c2) {
            return bitOr(equals(cipher, other, c2), lessThan(cipher, other, c2), c2);
        }

        /**
         * todo Public Function getRandomLtN(): get random in (1, public.n)
         *
         * @return BigInteger
         */
        public BigInteger getRandomLtN() {
            Random rand = new Random();
            BigInteger result;
            do {
                result = new BigInteger(0b0001_0100, rand).abs();
            } while (result.equals(BigInteger.ZERO));

            return result;
        }
    }

    public static class CloudPlatformThird {

        /**
         * publicKey: public key
         */
        final PaillierPublicKey publicKey;
        /**
         * privateKey: private key
         */
        final PaillierPrivateKey privateKey;

        /**
         * todo Public Function CloudPlatformThird(PaillierPublicKey): Class CloudPlatformThird Init
         *
         * @param publicKey  public key
         * @param privateKey private key
         */
        public CloudPlatformThird(PaillierPublicKey publicKey, PaillierPrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        /**
         * todo Public Function multiply(EncryptedNumber, EncryptedNumber): secure multiply protocol third
         *
         * @param h1 param 1
         * @param h2 param 2
         * @return EncryptedNumber
         */
        public EncryptedNumber multiply(EncryptedNumber h1, EncryptedNumber h2) {
            Object o1 = this.privateKey.decrypt(h1);
            Object o2 = this.privateKey.decrypt(h2);

            String o1c = o1 instanceof BigInteger ? "o1i" : "o1d";
            String o2c = o2 instanceof BigInteger ? "o2i" : "o2d";
            switch (o1c + o2c) {
                case "o1io2i": {
                    return this.publicKey.encrypt(((BigInteger) o1).multiply((BigInteger) o2));
                }
                case "o1io2d": {
                    return this.publicKey.encrypt(new BigDecimal((BigInteger) o1).multiply((BigDecimal) o2));
                }
                case "o1do2i": {
                    return this.publicKey.encrypt(((BigDecimal) o1).multiply(new BigDecimal((BigInteger) o2)));
                }
                case "o1do2d": {
                    return this.publicKey.encrypt(((BigDecimal) o1).multiply((BigDecimal) o2));
                }
                default:
                    throw new TypeErrorException("type of encrypted number is error in multiply process");
            }
        }

        /**
         * todo Public Function divide(EncryptedNumber, EncryptedNumber): secure divide protocol third
         *
         * @param h1 param 1
         * @param h2 param 2
         * @return EncryptedNumber
         */
        public EncryptedNumber divide(EncryptedNumber h1, EncryptedNumber h2) {
            Object o1 = this.privateKey.decrypt(h1);
            Object o2 = this.privateKey.decrypt(h2);

            String o1c = o1 instanceof BigInteger ? "o1i" : "o1d";
            String o2c = o2 instanceof BigInteger ? "o2i" : "o2d";
            MathContext mc = new MathContext(10, RoundingMode.HALF_UP);
            switch (o1c + o2c) {
                case "o1io2i": {
                    return this.publicKey.encrypt(((BigInteger) o1).divide((BigInteger) o2));
                }
                case "o1io2d": {
                    return this.publicKey.encrypt(new BigDecimal((BigInteger) o1).divide((BigDecimal) o2, mc));
                }
                case "o1do2i": {
                    return this.publicKey.encrypt(((BigDecimal) o1).divide(new BigDecimal((BigInteger) o2), mc));
                }
                case "o1do2d": {
                    return this.publicKey.encrypt(((BigDecimal) o1).divide((BigDecimal) o2, mc));
                }
                default:
                    throw new TypeErrorException("type of encrypted number is error in divide process");
            }
        }

        /**
         * todo Public Function optimum(EncryptedNumber, EncryptedNumber, EncryptedNumber, String): secure optimum protocol third
         *
         * @param h1   param 1
         * @param h2   param 2
         * @param h3   param 3
         * @param mode optimum mode 'max' or 'min'
         * @return ArrayList
         */
        public ArrayList<EncryptedNumber> optimum(EncryptedNumber h1, EncryptedNumber h2, EncryptedNumber h3, String mode) {
            Object o = this.privateKey.decrypt(h1);
            boolean v;
            if (o instanceof BigInteger) {
                v = Objects.equals(mode, "max") ? ((BigInteger) o).compareTo(BigInteger.ZERO) > 0 : ((BigInteger) o).compareTo(BigInteger.ZERO) < 0;
            } else if (o instanceof BigDecimal) {
                v = Objects.equals(mode, "max") ? ((BigDecimal) o).compareTo(BigDecimal.ZERO) > 0 : ((BigDecimal) o).compareTo(BigDecimal.ZERO) < 0;
            } else {
                throw new TypeErrorException("type of encrypted number is error in optimum process");
            }

            int alpha = v ? 1 : 0;

            return new ArrayList<>(Arrays.asList(this.publicKey.encrypt(alpha), alpha == 1 ? h3 : h2));
        }

        /**
         * todo Public Function parity(EncryptedNumber): secure parity protocol third
         *
         * @param h param
         * @return EncryptedNumber
         */
        public EncryptedNumber parity(EncryptedNumber h) {
            Object o = this.privateKey.decrypt(h);

            if (o instanceof BigInteger) {
                return ((BigInteger) o).mod(BigInteger.TWO).equals(BigInteger.ZERO) ? this.publicKey.encrypt(0) : this.publicKey.encrypt(1);
            } else if (o instanceof BigDecimal) {
                return ((BigDecimal) o).toBigInteger().mod(BigInteger.TWO).equals(BigInteger.ZERO) ? this.publicKey.encrypt(0) : this.publicKey.encrypt(1);
            } else {
                throw new TypeErrorException("type of encrypted number is error in parity process");
            }
        }

        /**
         * todo Public Function equals(EncryptedNumber): secure equals protocol third
         *
         * @param h param
         * @return EncryptedNumber
         */
        public EncryptedNumber equals(EncryptedNumber h) {
            Object o = this.privateKey.decrypt(h);

            if (o instanceof BigInteger) {
                return ((BigInteger) o).compareTo(BigInteger.ZERO) < 0 ? this.publicKey.encrypt(0) : this.publicKey.encrypt(1);
            } else if (o instanceof BigDecimal) {
                return ((BigDecimal) o).compareTo(BigDecimal.ZERO) < 0 ? this.publicKey.encrypt(0) : this.publicKey.encrypt(1);
            } else {
                throw new TypeErrorException("type of encrypted number is error in parity process");
            }
        }
    }

    /**
     * todo Public Static Class TypeErrorException: new TypeErrorException(str)
     */
    public static class TypeErrorException extends Error {
        /**
         * TypeErrorException
         *
         * @param s exception description
         */
        TypeErrorException(String s) {
            super(s);
        }
    }
}
