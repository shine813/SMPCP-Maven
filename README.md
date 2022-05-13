<h1 align='center' >SMPCP-Maven</h1>

<a href="https://github.com/shine813/SMPCP-Maven"><img src="https://img.shields.io/badge/smpcp_maven-1.0.0-green"></a>

---

## Background

<div align="justify">
The research of secure multi-party computation is mainly aimed at the problem of how to safely calculate a contract function in the absence of a trusted third party. 
Secure Multiparty Computation is the cryptographic basis for the implementation of many applications such as electronic elections, threshold signatures, and electronic auctions.

A secure multi-party computation protocol, if it is safe for attackers with unlimited computing power, is called information-theoretic security or unconditional security; 
if it is safe for attackers with polynomial computing power, it is called cryptography Learning safe or conditionally safe.

The existing results prove that under the unconditional security model, if and only when the number of malicious 
actors is less than 1/3 of the total number, a secure solution exists. Under the conditional security model, 
a safe solution exists if and only if the number of malicious actors is less than half of the total number.

Secure Multiparty Computation originated in 1982, the millionaire problem of
`Andrew Chi-Chih Yao`. Later, Oded Goldreich has a more detailed and systematic
discussion.

Base on [phe](https://github.com/data61/python-paillier) library implementation of the Secure Multi-Party
Computation Protocol, including:

- Secure Multiplication Protocol
- Secure Division Protocol
- Secure Maximum Calculation Protocol
- Secure Minimum Calculation Protocol
- Secure Parity Judgment Protocol
- Secure Binary AND Protocol
- Secure Binary OR Protocol
- Secure Binary Not Protocol
- Secure Binary XOR Protocol
- Secure Equal Protocol
- Secure Not Equal Protocol
- Secure Greater Than Protocol
- Secure Greater Equal Protocol
- Secure Less Than Protocol
- Secure Less Equal Protocol

---

## Environment

- `JDK15`
- `Maven3`

Package in `branches/mvn-repo`.

Maven in

```xml

<dependencies>
    <dependency>
        <groupId>cn.shine</groupId>
        <artifactId>SMPCP-Maven</artifactId>
        <version>1.0.0</version>
    </dependency>
</dependencies>

<repositories>
<repository>
    <id>SMPCP-Maven</id>
    <url>https://raw.github.com/shine813/SMPCP-Maven/mvn-repo/</url>
</repository>
</repositories>
```

See `pom.xml`。

---

## Example

See `src/main/java/cn/shine/APP.java`.

---

## Contact

Author：Shenyang Aerospace University-DSPC Zhan Shi

Github: https://github.com/shine813/

Email：phe.zshi@gmail.com

If you have any questions, please contact the author in time.
