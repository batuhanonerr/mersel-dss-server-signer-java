package io.mersel.dss.signer.api.services.keystore;

import io.mersel.dss.signer.api.exceptions.KeyStoreException;
import io.mersel.dss.signer.api.models.SigningKeyEntry;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * KeyStore yükleme ve imzalama anahtarlarını çözümleme servisi.
 * Yapılandırmaya göre uygun KeyStoreProvider'a delege eder.
 */
@Service
public class KeyStoreLoaderService {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreLoaderService.class);

    /**
     * Uygun sağlayıcı kullanarak KeyStore'u yükler.
     */
    public KeyStore loadKeyStore(KeyStoreProvider provider, char[] pin) {
        return provider.loadKeyStore(pin);
    }

    /**
     * Alias veya seri numarasına göre keystore'dan imzalama anahtar girdisini çözümler.
     * 
     * @param keyStore Yüklenmiş keystore
     * @param pin Private key'lere erişim için PIN
     * @param certificateAlias İsteğe bağlı sertifika alias'ı
     * @param certificateSerialNumber İsteğe bağlı sertifika seri numarası (hex formatında)
     * @return Alias ve private key girdisi içeren SigningKeyEntry
     */
    public SigningKeyEntry resolveKeyEntry(KeyStore keyStore, 
                                          char[] pin,
                                          String certificateAlias,
                                          String certificateSerialNumber) {
        try {
            KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(pin);

            if (StringUtils.hasText(certificateAlias) && keyStore.isKeyEntry(certificateAlias)) {
                try {
                    KeyStore.PrivateKeyEntry entry = getPrivateKeyEntry(keyStore, certificateAlias, protection);
                    LOGGER.info("İmzalama anahtarı alias ile bulundu: {}", certificateAlias);
                    return new SigningKeyEntry(certificateAlias, entry);
                } catch (Exception e) {
                    throw new KeyStoreException(
                        "Alias için imzalama anahtarı yüklenemedi: " + certificateAlias, e);
                }
            }

            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                
                if (!keyStore.isKeyEntry(alias)) {
                    continue;
                }

                try {
                    Certificate cert = keyStore.getCertificate(alias);
                    if (!matchesSerial(cert, certificateSerialNumber)) {
                        continue;
                    }

                    KeyStore.PrivateKeyEntry entry = getPrivateKeyEntry(keyStore, alias, protection);
                    LOGGER.info("İmzalama anahtarı seri numarası ile bulundu: {} (alias: {})", 
                        certificateSerialNumber, alias);
                    return new SigningKeyEntry(alias, entry);
                } catch (Exception e) {
                    LOGGER.debug("Hata nedeniyle alias atlandı: {} - {}", alias, e.getMessage());
                }
            }

            throw new KeyStoreException("Keystore'da uygun imzalama anahtarı bulunamadı");
            
        } catch (KeyStoreException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyStoreException("Keystore'dan imzalama anahtarı çözümlenemedi", e);
        }
    }

    /**
     * getEntry() çağrısından önce BouncyCastle'ın EC AlgorithmParameters desteğini garanti eder.
     *
     * SunPKCS11, HSM'den private key okurken CKA_EC_PARAMS attribute'unu parse etmek için
     * AlgorithmParameters.getInstance("EC") çağırır. JDK 8'in SunEC'si yalnızca named OID
     * destekler; HSM'ler (örn. mali mühür) explicit form döndürdüğünde IOException fırlatır.
     *
     * BC kaydı RSA anahtarlarını etkilemez, bu yüzden key tipinden bağımsız olarak
     * her getEntry() öncesinde koşulsuz çağrılır.
     */
    private KeyStore.PrivateKeyEntry getPrivateKeyEntry(KeyStore keyStore, 
                                                         String alias,
                                                         KeyStore.PasswordProtection protection) 
            throws Exception {
        ensureBouncyCastleRegistered();
        return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, protection);
    }

    /**
     * BouncyCastle'ın JCA provider listesinde kayıtlı olduğundan ve SunEC'nin
     * kaldırıldığından emin olur. İdempotent ve thread-safe.
     */
    private static synchronized void ensureBouncyCastleRegistered() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) != null 
                && Security.getProvider("SunEC") == null) {
            return;
        }

        Security.removeProvider("SunEC");

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }

        LOGGER.info("BouncyCastle EC AlgorithmParameters desteği etkinleştirildi, SunEC kaldırıldı");
    }

    /**
     * Sertifikanın yapılandırılmış seri numarası ile eşleşip eşleşmediğini kontrol eder.
     */
    private boolean matchesSerial(Certificate certificate, String configuredSerial) {
        if (!(certificate instanceof X509Certificate)) {
            return false;
        }

        if (!StringUtils.hasText(configuredSerial)) {
            return true;
        }

        try {
            String certSerial = ((X509Certificate) certificate).getSerialNumber().toString();
            String configuredNormalized = new BigInteger(configuredSerial, 16).toString();
            return configuredNormalized.equals(certSerial);
        } catch (NumberFormatException e) {
            LOGGER.warn("Geçersiz seri numarası formatı: {}", configuredSerial);
            return false;
        }
    }
}
