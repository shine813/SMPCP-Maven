package cn.shine.phe;

/*
 * @Project PHE-Maven
 * @Package cn.shine.phe
 * @Class   EncodedNumber
 * @Version 1.0.0
 * @Author  Zhan Shi
 * @Time    2022/5/9 16:20
 * @License MIT
 */


import org.apache.commons.math3.util.FastMath;
import org.jetbrains.annotations.NotNull;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;

/**
 * todo Public Class EncodedNumber: to encrypt and decrypt negative and floating point numbers
 *
 * @author Zhan Shi
 */
public class EncodedNumber {
    /**
     * BASE: the base when exponentiating, the larger the BASE, the less information is leaked
     */
    public static final Integer BASE = 16;
    /**
     * LOG2_BASE: log2(BASE) -> 4
     */
    public static final Integer LOG2_BASE = 4;
    /**
     * MANTISSA_BITS: Double type mantissa bits -> 52
     */
    public static final Integer MANTISSA_BITS = 52;
    /**
     * publicKey: the public key of ciphertext
     */
    public Paillier.PaillierPublicKey publicKey;
    /**
     * encoding:  the ciphertext encoding
     * exponent:  ciphertext exponent
     */
    public BigInteger encoding, exponent;

    /**
     * todo Public Function EncodedNumber(PaillierPublicKey, BigInteger, BigInteger): Class EncodedNumber init
     *
     * @param publicKey the public key of ciphertext
     * @param encoding  ciphertext encoding
     * @param exponent  ciphertext exponent
     */
    public EncodedNumber(Paillier.PaillierPublicKey publicKey, BigInteger encoding, BigInteger exponent) {
        this.publicKey = publicKey;
        this.encoding = encoding;
        this.exponent = exponent;
    }

    /**
     * @param publicKey the public key of ciphertext
     * @param scalar    scalar to be encoded, must be BigInteger or BigDecimal
     * @return EncodedNumber
     * @throws Util.ValueErrorException if some value is lager than publicKey.maxInt
     * @throws Util.TypeErrorException  if class of scalar is not BigInteger or BigDecimal
     * @see EncodedNumber#encode(Paillier.PaillierPublicKey, Object, Double, Integer)
     */
    public static @NotNull EncodedNumber encode(@NotNull Paillier.PaillierPublicKey publicKey, Object scalar) throws Util.ValueErrorException, Util.TypeErrorException {
        return encode(publicKey, scalar, null, null);
    }

    /**
     * @param publicKey the public key of ciphertext
     * @param scalar    scalar to be encoded, must be BigInteger or BigDecimal
     * @param precision encoding precision
     * @return EncodedNumber
     * @throws Util.ValueErrorException if some value is lager than publicKey.maxInt
     * @throws Util.TypeErrorException  if class of scalar is not BigInteger or BigDecimal
     * @see EncodedNumber#encode(Paillier.PaillierPublicKey, Object, Double, Integer)
     */
    public static @NotNull EncodedNumber encode(@NotNull Paillier.PaillierPublicKey publicKey, Object scalar, Double precision) throws Util.ValueErrorException, Util.TypeErrorException {
        return encode(publicKey, scalar, precision, null);
    }

    /**
     * todo Public Static Function encode(PaillierPublicKey, Object, Double, Integer): Ciphertext encoding
     *
     * @param publicKey   the public key of ciphertext
     * @param scalar      scalar to be encoded, must be BigInteger or BigDecimal
     * @param precision   encoding precision
     * @param maxExponent encoding maximum exponent
     * @return EncodedNumber
     * @throws Util.ValueErrorException if some value is lager than publicKey.maxInt
     * @throws Util.TypeErrorException  if class of scalar is not BigInteger or BigDecimal
     */
    public static @NotNull EncodedNumber encode(@NotNull Paillier.PaillierPublicKey publicKey, Object scalar, Double precision, Integer maxExponent) throws Util.ValueErrorException, Util.TypeErrorException {
        scalar = Util.wrapBig(scalar);
        BigInteger preExponent;
        if (precision == null) {
            if (scalar instanceof BigInteger) {
                preExponent = BigInteger.ZERO;
            } else if (scalar instanceof BigDecimal) {
                BigDecimal scalarBigDecimal = (BigDecimal) scalar;
                // get scalar exp
                Integer binFltExponent = Util.Frexp.frexp(scalarBigDecimal.doubleValue()).exponent;
                BigDecimal binLsbExponent = BigDecimal.valueOf(binFltExponent - MANTISSA_BITS);
                // number with exponent <- floor(exp / log_2(16))
                BigDecimal exponentBigDecimal = binLsbExponent.divide(BigDecimal.valueOf(LOG2_BASE), RoundingMode.FLOOR);
                preExponent = exponentBigDecimal.toBigInteger();
            } else {
                throw new Util.TypeErrorException(String.format("Don't know the precision of type %s", scalar.getClass()));
            }
        } else {
            preExponent = BigDecimal.valueOf(FastMath.floor(FastMath.log(precision, BASE))).toBigInteger();
        }

        BigInteger exponent;
        if (maxExponent == null) {
            exponent = preExponent;
        } else {
            exponent = BigInteger.valueOf(FastMath.min(maxExponent, preExponent.intValue()));
        }

        // convert double expand to int by multiplication and precision
        BigInteger intRep;
        BigDecimal intRepBigDecimal;
        if (scalar instanceof BigInteger) {
            BigDecimal turnScalar = new BigDecimal((BigInteger) scalar);
            intRepBigDecimal = turnScalar.multiply(BigDecimal.valueOf(FastMath.pow(BASE, -exponent.intValue())));
        } else if (scalar instanceof BigDecimal) {
            BigDecimal scalarBigDecimal = ((BigDecimal) scalar);
            intRepBigDecimal = scalarBigDecimal.multiply(BigDecimal.valueOf(FastMath.pow(BASE, -exponent.intValue())));
        } else {
            throw new Util.TypeErrorException(String.format("Don't know the precision of type %s", scalar.getClass()));
        }
        intRep = intRepBigDecimal.setScale(0, RoundingMode.HALF_UP).toBigInteger();

        if (intRep.abs().compareTo(publicKey.maxInt) > 0) {
            String exception = "Integer needs to be within +/- %s but got %s";
            throw new Util.ValueErrorException(String.format(exception, publicKey.maxInt, intRep.abs()));
        }

        return new EncodedNumber(publicKey, intRep.mod(publicKey.n), exponent);
    }

    /**
     * todo Public Function decode(): Ciphertext decoding
     *
     * @return Object -> BigInteger or BigDecimal
     * @throws Util.ValueErrorException if this#encoding is larger than publicKey#n
     * @throws StackOverflowError  if decode numeric overflow
     */
    public Object decode() throws Util.ValueErrorException, StackOverflowError {
        BigInteger mantissa;

        if (this.encoding.compareTo(this.publicKey.n) >= 0) {
            throw new Util.ValueErrorException("Attempted to decode corrupted number");
        } else if (this.encoding.compareTo(this.publicKey.maxInt) <= 0) {
            mantissa = this.encoding;
        } else if (this.encoding.compareTo(this.publicKey.n.subtract(this.publicKey.maxInt)) >= 0) {
            mantissa = this.encoding.subtract(this.publicKey.n);
        } else {
            throw new Util.OverflowErrorException("Overflow detected in decrypted number");
        }

        if (this.exponent.compareTo(BigInteger.ZERO) >= 0) {
            BigInteger decoding = BigDecimal.valueOf(FastMath.pow(BASE, this.exponent.intValue())).toBigInteger();
            // double to int by multiplication
            return mantissa.multiply(decoding);
        } else {
            try {
                // double to double by division
                return BigDecimal.valueOf(mantissa.doubleValue() / FastMath.pow(BASE, -this.exponent.intValue()));
            } catch (Exception e) {
                throw new Util.OverflowErrorException(String.format("decoded result too large for a float: from %s", e));
            }
        }
    }

    /**
     * todo Public Function decreaseExponentTo(BigInteger): decrease exponent
     *
     * @param newExp new exponent
     * @return EncodeNumber
     * @throws Util.ValueErrorException if newExp > this.exponent
     */
    public EncodedNumber decreaseExponentTo(@NotNull BigInteger newExp) throws Util.ValueErrorException {
        if (newExp.compareTo(this.exponent) > 0) {
            String exception = "New exponent %s should be more negative than old exponent %s";
            throw new Util.ValueErrorException(String.format(exception, newExp, this.exponent));
        }

        BigDecimal factor = BigDecimal.valueOf(FastMath.pow(BASE, this.exponent.subtract(newExp).intValue()));
        BigInteger newEnc = Util.mulMod(this.encoding, factor.toBigInteger(), this.publicKey.n);

        return new EncodedNumber(this.publicKey, newEnc, newExp);
    }
}
