package io.mersel.dss.signer.api.util;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECParameterSpec;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CryptoUtilsSignatureAlgorithmTest {

    @Test
    void rsaKey_shouldReturnSha256WithRsa() {
        RSAPrivateKey key = mock(RSAPrivateKey.class);
        assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key));
    }

    @Test
    void ecKeyP256_shouldReturnSha256WithEcdsa() {
        ECPrivateKey key = mockECKey(256);
        assertEquals("SHA256withECDSA", CryptoUtils.getSignatureAlgorithm(key));
    }

    @Test
    void ecKeyP384_shouldReturnSha384WithEcdsa() {
        ECPrivateKey key = mockECKey(384);
        assertEquals("SHA384withECDSA", CryptoUtils.getSignatureAlgorithm(key));
    }

    @Test
    void ecKeyP521_shouldReturnSha512WithEcdsa() {
        ECPrivateKey key = mockECKey(521);
        assertEquals("SHA512withECDSA", CryptoUtils.getSignatureAlgorithm(key));
    }

    @Test
    void withCertificate_shouldUseCertSigAlgName() {
        RSAPrivateKey key = mock(RSAPrivateKey.class);
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSigAlgName()).thenReturn("SHA384withECDSA");

        assertEquals("SHA384withECDSA", CryptoUtils.getSignatureAlgorithm(key, cert));
    }

    @Test
    void withNullCertificate_shouldFallbackToKeyBased() {
        RSAPrivateKey key = mock(RSAPrivateKey.class);
        assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key, null));
    }

    @Test
    void unknownKeyWithEcAlgorithm_shouldReturnEcdsa() {
        java.security.PrivateKey key = mock(java.security.PrivateKey.class);
        when(key.getAlgorithm()).thenReturn("EC");
        assertEquals("SHA256withECDSA", CryptoUtils.getSignatureAlgorithm(key));
    }

    @Test
    void unknownKeyWithRsaAlgorithm_shouldReturnRsa() {
        java.security.PrivateKey key = mock(java.security.PrivateKey.class);
        when(key.getAlgorithm()).thenReturn("RSA");
        assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key));
    }

    private ECPrivateKey mockECKey(int bitLength) {
        ECPrivateKey key = mock(ECPrivateKey.class);
        ECParameterSpec params = mock(ECParameterSpec.class);
        BigInteger order = BigInteger.valueOf(2).pow(bitLength).subtract(BigInteger.ONE);
        when(params.getOrder()).thenReturn(order);
        when(key.getParams()).thenReturn(params);
        return key;
    }
}
