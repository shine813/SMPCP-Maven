package cn.shine.phe;

/*
 * @Project PHE-Maven
 * @Package cn.shine.phe
 * @Class   Util
 * @Version 1.0.0
 * @Author  Zhan Shi
 * @Time    2022/5/7 21:51
 * @License MIT
 */

import org.jetbrains.annotations.NotNull;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Objects;
import java.util.Random;

/**
 * todo Public Class Util: the util of phe project
 *
 * @author Zhan Shi
 */
public class Util {
    /**
     * todo Public Static getRandBits(Integer): get the random bits with n length
     *
     * @param n length of random bits
     * @return BigInteger
     */
    public static @NotNull BigInteger getRandBits(Integer n) {
        StringBuilder bits = new StringBuilder();
        for (int i = 0; i < n; i++) {
            Integer bit = new Random().nextInt(2);
            bits.append(bit);
        }
        // set the (n-1)th position to 1
        bits.replace(n - 2, n - 1, "1");

        return new BigInteger(String.valueOf(bits), 2);
    }

    /**
     * todo Public Static getPrimeOver(Integer): get the prime with n length
     *
     * @param n length of prime
     * @return BigInteger
     */
    public static BigInteger getPrimeOver(Integer n) {
        BigInteger randBits = getRandBits(n);
        BigInteger prime;
        do {
            prime = randBits.nextProbablePrime();
        } while (prime.equals(randBits));

        return prime;
    }

    /**
     * todo Public Static Function invert(BigInteger, BigInteger): the function of inverting
     *
     * @param a the param a
     * @param b the param b
     * @return BigInteger a ** -1 mod b
     * @throws ZeroDivisionErrorException if a.modInverse(b) == 0
     */
    public static @NotNull BigInteger invert(@NotNull BigInteger a, BigInteger b) throws ZeroDivisionErrorException {
        BigInteger s = a.modInverse(b);
        if (s.equals(BigInteger.ZERO)) {
            throw new ZeroDivisionErrorException("invert() no inverse exists");
        }

        return s;
    }

    /**
     * todo Public Static Function mulMod(BigInteger, BigInteger, BigInteger): multiplication modulo
     *
     * @param a param a
     * @param b param b
     * @param c param c
     * @return BigInteger
     */
    public static @NotNull BigInteger mulMod(@NotNull BigInteger a, @NotNull BigInteger b, BigInteger c) {
        return a.multiply(b).mod(c);
    }

    /**
     * todo Public Static Class ValueErrorException: new ValueErrorException(str)
     */
    public static class ValueErrorException extends Error {
        /**
         * ValueErrorException
         *
         * @param s exception description
         */
        ValueErrorException(String s) {
            super(s);
        }
    }

    /**
     * todo Public Static Class ZeroDivisionErrorException: new ZeroDivisionErrorException(str)
     */
    public static class ZeroDivisionErrorException extends Error {
        /**
         * ZeroDivisionErrorException
         *
         * @param s exception description
         */
        ZeroDivisionErrorException(String s) {
            super(s);
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

    /**
     * todo Public Static Class NotImplementedErrorException: new NotImplementedErrorException(str)
     */
    public static class NotImplementedErrorException extends Error {
        /**
         * NotImplementedErrorException
         *
         * @param s exception description
         */
        NotImplementedErrorException(String s) {
            super(s);
        }
    }

    /**
     * todo Public Static Class OverflowErrorException: new OverflowErrorException(str)
     */
    public static class OverflowErrorException extends Error {
        /**
         * OverflowErrorException
         *
         * @param s exception description
         */
        OverflowErrorException(String s) {
            super(s);
        }
    }

    /**
     * todo Public Static Class Frexp: Class Frexp, like math.frexp() in python and frexp() in cpp
     *
     * @author waman
     * <a href="https://github.com/waman/conformal/blob/master/src/test/java/java_algorithm/function/elementary/Log.java">https://github.com/waman/conformal/blob/master/src/test/java/java_algorithm/function/elementary/Log.java</a>
     */
    public static class Frexp {
        /**
         * mantissa: the mantissa of number
         */
        Double mantissa;
        /**
         * exponent: the exponent of number
         */
        Integer exponent;

        /**
         * todo Public Function Frexp(): Class Frexp init
         */
        public Frexp() {
            this.mantissa = 0.;
            this.exponent = 0;
        }

        /**
         * todo Public Static Function frexp(Double): a method of implement frexp() with java
         *
         * @param num the number
         * @return Frexp num = this.mantissa * 2. ** this.exponent
         */
        public static @NotNull Frexp frexp(Double num) {
            Frexp result = new Frexp();
            // 2^-52
            double bias = Double.longBitsToDouble(0x3ca0_000_000_000_000L);
            long bits = Double.doubleToLongBits(num);
            result.exponent = (int) ((bits >> 52) & 0x7ffL);
            int s = (bits & 0x8_000_000_000_000_000L) != 0 ? -1 : 1;
            bits &= 0xfffffffffffffL;
            if (result.exponent != 0) {
                // normal number
                bits |= 0x10_000_000_000_000L;
            }
            result.mantissa = bits * s * bias;
            result.exponent -= 1022;
            return result;
        }
    }

    /**
     * todo Public Static wrapBig(Object): turn n to BigClass
     *
     * @param n number
     * @return Object -> BigInteger or BigDecimal
     */
    public static @NotNull Object wrapBig(@NotNull Object n) {
        if (n instanceof Integer) {
            return new BigInteger(n.toString());
        } else if (n instanceof Float || n instanceof Double || n instanceof BigDecimal) {
            String[] nums = String.valueOf(n).split("\\.");
            String zero = "0";

            if (nums.length == 1) {
                return new BigInteger(n.toString());
            }

            if (Objects.equals(nums[1], zero)) {
                return new BigInteger(nums[0]);
            } else {
                return new BigDecimal(String.valueOf(n));
            }
        } else {
            return n;
        }
    }
}
