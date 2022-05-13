package cn.shine;

/*
 * @Project SMPCP-Maven
 * @Package cn.shine.smpcp
 * @Class   AppTest
 * @Version 1.0.0
 * @Author  Zhan Shi
 * @Time    2022/5/12 22:49
 * @License MIT
 */

import cn.shine.phe.Paillier;
import cn.shine.report.ZTestReport;
import cn.shine.smpcp.Protocol;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.Random;

import static junit.framework.TestCase.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Secure Multi-Party Computation Protocol Test
 *
 * @author Zhan Shi
 */
@Listeners({ZTestReport.class})
public class AppTest {
    /**
     * todo DataProvider keyLengthsProvider
     *
     * @return Object[][] -> {{int}, ...}
     */
    @DataProvider(name = "keyLength")
    public Object[][] keyLengthsProvider() {
        return new Object[][]{{128}, {256}, {512}, {1024}, {2048},{3072}, {4096}};
    }

    /**
     * todo Test mulIntTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Integer multiply test", dataProvider = "keyLength")
    public void mulIntTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);
        Protocol.CloudPlatform cloud1 = new Protocol.CloudPlatform(keyPair.publicKey);
        Protocol.CloudPlatformThird cloud2 = new Protocol.CloudPlatformThird(keyPair.publicKey, keyPair.privateKey);
        Protocol.SMPCProtocol protocol = new Protocol.SMPCProtocol(cloud1, cloud2);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));
        Protocol.SMPCProtocol n1 = protocol.encode(keyPair.publicKey.encrypt(m1));
        Paillier.EncryptedNumber n2 = keyPair.publicKey.encrypt(m2);

        assertEquals(keyPair.privateKey.decrypt(n1.multiply(n2)), m1.multiply(m2));
    }

    /**
     * todo Test mulDouTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Double multiply test", dataProvider = "keyLength")
    public void mulDouTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);
        Protocol.CloudPlatform cloud1 = new Protocol.CloudPlatform(keyPair.publicKey);
        Protocol.CloudPlatformThird cloud2 = new Protocol.CloudPlatformThird(keyPair.publicKey, keyPair.privateKey);
        Protocol.SMPCProtocol protocol = new Protocol.SMPCProtocol(cloud1, cloud2);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m1 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m2 = randomDec(BigInteger.valueOf(keyLength)).add(random);

        Protocol.SMPCProtocol n1 = protocol.encode(keyPair.publicKey.encrypt(m1));
        Paillier.EncryptedNumber n2 = keyPair.publicKey.encrypt(m2);

        assertTrue(((BigDecimal) keyPair.privateKey.decrypt(n1.multiply(n2)))
                .subtract(m1.multiply(m2)).compareTo(BigDecimal.valueOf(1e-3)) <= 0);
    }

    /**
     * todo Test divIntTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Integer divide test", dataProvider = "keyLength")
    public void divIntTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);
        Protocol.CloudPlatform cloud1 = new Protocol.CloudPlatform(keyPair.publicKey);
        Protocol.CloudPlatformThird cloud2 = new Protocol.CloudPlatformThird(keyPair.publicKey, keyPair.privateKey);
        Protocol.SMPCProtocol protocol = new Protocol.SMPCProtocol(cloud1, cloud2);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));
        Protocol.SMPCProtocol n1 = protocol.encode(keyPair.publicKey.encrypt(m1));
        Paillier.EncryptedNumber n2 = keyPair.publicKey.encrypt(m2);

        assertEquals(keyPair.privateKey.decrypt(n1.divide(n2)), m1.divide(m2));
    }

    /**
     * todo Test divDouTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Double divide test", dataProvider = "keyLength")
    public void divDouTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);
        Protocol.CloudPlatform cloud1 = new Protocol.CloudPlatform(keyPair.publicKey);
        Protocol.CloudPlatformThird cloud2 = new Protocol.CloudPlatformThird(keyPair.publicKey, keyPair.privateKey);
        Protocol.SMPCProtocol protocol = new Protocol.SMPCProtocol(cloud1, cloud2);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m1 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m2 = randomDec(BigInteger.valueOf(keyLength)).add(random);

        Protocol.SMPCProtocol n1 = protocol.encode(keyPair.publicKey.encrypt(m1));
        Paillier.EncryptedNumber n2 = keyPair.publicKey.encrypt(m2);

        assertTrue(((BigDecimal) keyPair.privateKey.decrypt(n1.divide(n2)))
                .subtract(m1.divide(m2, 20, RoundingMode.HALF_UP)).compareTo(BigDecimal.valueOf(1e-3)) <= 0);
    }

    /**
     * todo Test optimumTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Optimum test", dataProvider = "keyLength")
    public void optimumTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);
        Protocol.CloudPlatform cloud1 = new Protocol.CloudPlatform(keyPair.publicKey);
        Protocol.CloudPlatformThird cloud2 = new Protocol.CloudPlatformThird(keyPair.publicKey, keyPair.privateKey);
        Protocol.SMPCProtocol protocol = new Protocol.SMPCProtocol(cloud1, cloud2);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));
        Protocol.SMPCProtocol n1 = protocol.encode(keyPair.publicKey.encrypt(m1));
        Paillier.EncryptedNumber n2 = keyPair.publicKey.encrypt(m2);


        assertEquals(keyPair.privateKey.decrypt(n1.optimum(n2, "max")), m1.max(m2));
        assertEquals(keyPair.privateKey.decrypt(n1.optimum(n2, "min")), m1.min(m2));
    }

    /**
     * todo Test bitTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Bit test", dataProvider = "keyLength")
    public void bitTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);
        Protocol.CloudPlatform cloud1 = new Protocol.CloudPlatform(keyPair.publicKey);
        Protocol.CloudPlatformThird cloud2 = new Protocol.CloudPlatformThird(keyPair.publicKey, keyPair.privateKey);
        Protocol.SMPCProtocol protocol = new Protocol.SMPCProtocol(cloud1, cloud2);

        BigInteger m1 = BigInteger.ONE;
        BigInteger m2 = BigInteger.ZERO;
        Protocol.SMPCProtocol n1 = protocol.encode(keyPair.publicKey.encrypt(m1));
        Paillier.EncryptedNumber n2 = keyPair.publicKey.encrypt(m2);


        assertEquals(keyPair.privateKey.decrypt(n1.bitAnd(n2)), BigInteger.ZERO);
        assertEquals(keyPair.privateKey.decrypt(n1.bitOr(n2)), BigInteger.ONE);
        assertEquals(keyPair.privateKey.decrypt(n1.bitNot()), BigInteger.ZERO);
        assertEquals(keyPair.privateKey.decrypt(n1.bitXor(n2)), BigInteger.ONE);
    }

    /**
     * todo Test equalsTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Equals test", dataProvider = "keyLength")
    public void equalsTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);
        Protocol.CloudPlatform cloud1 = new Protocol.CloudPlatform(keyPair.publicKey);
        Protocol.CloudPlatformThird cloud2 = new Protocol.CloudPlatformThird(keyPair.publicKey, keyPair.privateKey);
        Protocol.SMPCProtocol protocol = new Protocol.SMPCProtocol(cloud1, cloud2);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));
        Protocol.SMPCProtocol n1 = protocol.encode(keyPair.publicKey.encrypt(m1));
        Paillier.EncryptedNumber n2 = keyPair.publicKey.encrypt(m2);


        assertEquals(keyPair.privateKey.decrypt(n1.equals(n2)), m1.equals(m2) ? BigInteger.ONE : BigInteger.ZERO);
        assertEquals(keyPair.privateKey.decrypt(n1.notEquals(n2)), !m1.equals(m2) ? BigInteger.ONE : BigInteger.ZERO);
    }

    /**
     * todo Test greaterTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Greater test", dataProvider = "keyLength")
    public void greaterTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);
        Protocol.CloudPlatform cloud1 = new Protocol.CloudPlatform(keyPair.publicKey);
        Protocol.CloudPlatformThird cloud2 = new Protocol.CloudPlatformThird(keyPair.publicKey, keyPair.privateKey);
        Protocol.SMPCProtocol protocol = new Protocol.SMPCProtocol(cloud1, cloud2);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));
        Protocol.SMPCProtocol n1 = protocol.encode(keyPair.publicKey.encrypt(m1));
        Paillier.EncryptedNumber n2 = keyPair.publicKey.encrypt(m2);


        assertEquals(keyPair.privateKey.decrypt(n1.greaterThan(n2)), m1.compareTo(m2) > 0 ? BigInteger.ONE :
                BigInteger.ZERO);
        assertEquals(keyPair.privateKey.decrypt(n1.greaterEquals(n2)), m1.compareTo(m2) >= 0 ? BigInteger.ONE :
                BigInteger.ZERO);
    }

    /**
     * todo Test lessTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Less test", dataProvider = "keyLength")
    public void lessTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);
        Protocol.CloudPlatform cloud1 = new Protocol.CloudPlatform(keyPair.publicKey);
        Protocol.CloudPlatformThird cloud2 = new Protocol.CloudPlatformThird(keyPair.publicKey, keyPair.privateKey);
        Protocol.SMPCProtocol protocol = new Protocol.SMPCProtocol(cloud1, cloud2);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));
        Protocol.SMPCProtocol n1 = protocol.encode(keyPair.publicKey.encrypt(m1));
        Paillier.EncryptedNumber n2 = keyPair.publicKey.encrypt(m2);


        assertEquals(keyPair.privateKey.decrypt(n1.lessThan(n2)), m1.compareTo(m2) < 0 ? BigInteger.ONE :
                BigInteger.ZERO);
        assertEquals(keyPair.privateKey.decrypt(n1.lessEquals(n2)), m1.compareTo(m2) <= 0 ? BigInteger.ONE :
                BigInteger.ZERO);
    }

    /**
     * todo Private Function randomInt(BigInteger): generate random BigInteger
     *
     * @param n a bit length of BigInteger
     * @return BigInteger
     */
    @Contract("_ -> new")
    private @NotNull BigInteger randomInt(@NotNull BigInteger n) {
        Random rand = new Random();
        BigInteger result;
        do {
            result = new BigInteger(n.bitLength(), rand).abs();
        } while (result.equals(BigInteger.ZERO));

        return new BigInteger(n.bitLength(), rand);
    }

    /**
     * todo Private Function randomDec(BigInteger): generate random BigDecimal
     *
     * @param n a bit length of BigInteger
     * @return BigDecimal
     */
    @Contract("_ -> new")
    private @NotNull BigDecimal randomDec(BigInteger n) {
        return new BigDecimal(randomInt(n));
    }
}
