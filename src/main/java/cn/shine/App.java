package cn.shine;

/*
 * @Project SMPCP-Maven
 * @Package cn.shine
 * @Class   App
 * @Version 1.0.0
 * @Author  Zhan Shi
 * @Time    2022/5/12 22:50
 * @License MIT
 */

import cn.shine.phe.Paillier.EncryptedNumber;
import cn.shine.phe.Paillier.PaillierKeyPair;
import cn.shine.smpcp.Protocol.CloudPlatform;
import cn.shine.smpcp.Protocol.CloudPlatformThird;
import cn.shine.smpcp.Protocol.SMPCProtocol;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;


/**
 * Secure Multi-Party Computation Protocol
 * <p>
 * Python Library <p>
 * Secure-Multi-Party-Computation-Protocol <p>
 * <a href="https://github.com/shine813/Secure-Multi-Party-Computation-Protocol">https://github.com/shine813/Secure-Multi-Party-Computation-Protocol</a>
 * <p>
 * Java Library <p>
 * |- title:     smpcp-java <p>
 * |- summary:   Secure Multi-Party Computation Protocol <p>
 * |- uri:       <a href="https://github.com/shine813/SMPCP-Maven">https://github.com/shine813/SMPCP-Maven</a>
 * |- version:   1.0.0 <p>
 * |- author:    Zhan Shi <p>
 * |- email:     phe.zshi@gmail.com <p>
 * |- license:   MIT <p>
 * |- copyright: Copyright (c) 2021 Zhan Shi
 *
 * @author Zhan Shi
 */
public class App {
    /**
     * Example
     *
     * @param args some args
     */
    public static void main(String[] args) {
        PaillierKeyPair keyPair = PaillierKeyPair.generate(4096);
        CloudPlatform cloud1 = new CloudPlatform(keyPair.publicKey);
        CloudPlatformThird cloud2 = new CloudPlatformThird(keyPair.publicKey, keyPair.privateKey);
        SMPCProtocol protocol = new SMPCProtocol(cloud1, cloud2);

        SMPCProtocol n1 = protocol.encode(keyPair.publicKey.encrypt(6.2));
        EncryptedNumber n2 = keyPair.publicKey.encrypt(3.2);

        SMPCProtocol b1 = protocol.encode(keyPair.publicKey.encrypt(1));
        EncryptedNumber b2 = keyPair.publicKey.encrypt(0);

        assert keyPair.privateKey.decrypt(n1.decode()).equals(BigDecimal.valueOf(6.2));

        assert ((BigDecimal) keyPair.privateKey.decrypt(n1.multiply(n2))).setScale(2, RoundingMode.HALF_UP)
                .equals(BigDecimal.valueOf(19.84));

        assert keyPair.privateKey.decrypt(n1.divide(n2)).equals(BigDecimal.valueOf(1.9375));

        assert keyPair.privateKey.decrypt(n1.optimum(n2, "max")).equals(BigDecimal.valueOf(6.2));

        assert keyPair.privateKey.decrypt(n1.optimum(n2, "min")).equals(BigDecimal.valueOf(3.2));

        assert keyPair.privateKey.decrypt(n1.parity()).equals(BigInteger.ZERO);
        assert keyPair.privateKey.decrypt(protocol.encode(n2).parity()).equals(BigInteger.ONE);

        assert keyPair.privateKey.decrypt(b1.bitOr(b2)).equals(BigInteger.ONE);

        assert keyPair.privateKey.decrypt(b1.bitAnd(b2)).equals(BigInteger.ZERO);

        assert keyPair.privateKey.decrypt(b1.bitNot()).equals(BigInteger.ZERO);

        assert keyPair.privateKey.decrypt(b1.bitXor(b2)).equals(BigInteger.ONE);

        assert keyPair.privateKey.decrypt(n1.equals(n2)).equals(BigInteger.ZERO);

        assert keyPair.privateKey.decrypt(n1.notEquals(n2)).equals(BigInteger.ONE);

        assert keyPair.privateKey.decrypt(n1.greaterThan(n2)).equals(BigInteger.ONE);

        assert keyPair.privateKey.decrypt(n1.greaterEquals(n2)).equals(BigInteger.ONE);

        assert keyPair.privateKey.decrypt(n1.lessThan(n2)).equals(BigInteger.ZERO);

        assert keyPair.privateKey.decrypt(n1.lessEquals(n2)).equals(BigInteger.ZERO);
    }
}
