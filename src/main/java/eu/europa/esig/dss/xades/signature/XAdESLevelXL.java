// @formatter:off

/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationData;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.definition.xades141.XAdES141Element;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_XL;

/*
 * ########################OVERRIDE_DSS#########################
 * ####  DİKKAT: BU DÖKÜMAN, STANDART DSS KODUNDAN ZİYADE  ####
 * ####  SIFIRDAN YAZILMIŞTIR. ORİJİNAL OVERRIDE YAKLAŞIMI  ####
 * ####  DEĞİL, CACHE YÖNETİMİ VE XAdES 1.4.1 UYUMLULUĞU   ####
 * ####  ODAKLI ÖZEL TÜRKİYE İÇİN UYGULANMIŞTIR.            ####
 * #############################################################
 *
 * 1) Revocation (ve timestamp) validasyon verilerinin saklanması ve yeniden kullanılabilmesi önceliklidir.
 *    Burada cache ve validation-data yönetimine özel geliştirmeler ana motivasyondur. Yani, sadece
 *    imza zinciri ve doğrulama için dışarıdan gelen kaynaklar tekrar tekrar sorgulanmaz, gereken
 *    şekilde cache'den çekilir/kullanılır.
 *
 * 2) Tübitak'ın XAdES 1.4.1 profilinde tanımladığı gibi, timestamp validasyon verileri
 *    XAdES-X düzeyindeki <xades:RevocationValues> veya <xades:CertificateValues> bloklarından
 *    genelden ayrılarak yalnızca <xades141:TimestampValidationData> alanında kapsüllenmiştir.
 *    Yani, zamana bağlı doğrulama için kullanılan ek bilgiler (ör: dış OCSP/CRL, ek sertifikalar)
 *    artık shared/generic alanlar yerine, direk olarak sadece zamana-mühür validasyonunun altına
 *    XAdES141 namespace'iyle geçirilir ve ayrıştırılır. Bu hem şematik hem fonksiyonel ayrımı
 *    sağlar.
 *
 * 3) Söz konusu kod, Tübitak'ın yayımladığı e-İmza Kılavuzlarına/formatlarına ve Türkiye
 *    dokümantasyonuna uygun olacak şekilde kapsülleme ve doğrulama veri yönetimini gerçekleştirir.
 *
 * 4) Temel farklar:
 *    - XAdES 1.4.1 uyumlu <xades141:TimestampValidationData> node kullanımı.
 *    - Revocation (CRL/OCSP) değerlerinin ve ilgili sertifikaların, timestamp'in dışındaki
 *      doğrulama gereksinimlerinden ayrık şekilde işlenmesi.
 *    - Imza seviyesi güncellemelerinde (XL+ seviyelerine yükseltmede), bu ayrık veri modellerine 
 *      uygun olarak validation-data segmentlerinin ilgili alt alanlarda oluşturulması ve yönetilmesi.
 *    - DSS'nin generic cache/validation-data mekanizmaları, Türkiye uygulama ihtiyacına uygun şekilde,
 *      hem signature-chain hem de zaman damgası altındaki tokenlar için revize edilmiştir.
 *
 * 5) Kendi içinde, TÜBİTAK'ın kamu uygulamalarında zorunlu tuttuğu şema ve geçerlilik gereklilikleri
 *    sağlanır.
 *  
 * 6) Kodun kalanında, "XAdES 1.4.1 REVOCATION/TIMESTAMP VALIDATION DATA HANDLING" etiketli bölümlerde
 *    ayrımın ve özel modellemenin detaylarına yer verilmiştir, gerekirse ilgili fonksiyonlarda
 *    açıklama ve ek loglama ile takip edilebilir.
 */



/**
 * XL profile of XAdES signature
 *
 */
public class XAdESLevelXL extends XAdESLevelX {
    private static final Logger LOGGER = LoggerFactory.getLogger(XAdESLevelXL.class);

    /**
     * The default constructor for XAdESLevelXL.
     *
     * @param certificateVerifier {@link CertificateVerifier}
     */
    public XAdESLevelXL(final CertificateVerifier certificateVerifier) {
        super(certificateVerifier);
    }

    /**
     * Adds CertificateValues and RevocationValues segments to UnsignedSignatureProperties.<br>
     *
     * An XML electronic signature MAY contain at most one:<br>
     * - CertificateValues element and<br>
     * - RevocationValues element.
     *
     * @see XAdESLevelX#extendSignatures(List)
     */
    @Override
    protected void extendSignatures(List<AdvancedSignature> signatures) {
        super.extendSignatures(signatures);

        final List<AdvancedSignature> signaturesToExtend = getExtendToXLLevelSignatures(signatures);
        if (Utils.isCollectionEmpty(signaturesToExtend)) {
            return;
        }

        for (AdvancedSignature signature : signatures) {
            initializeSignatureBuilder((XAdESSignature) signature);

            // NOTE: do not force sources reload for certificate and revocation sources
            // in order to ensure the same validation data as on -C level
            xadesSignature.resetTimestampSource();
        }

        final SignatureRequirementsChecker signatureRequirementsChecker = getSignatureRequirementsChecker();
        if (XAdES_XL.equals(params.getSignatureLevel())) {
            signatureRequirementsChecker.assertExtendToXLLevelPossible(signatures);
        }
        signatureRequirementsChecker.assertSignaturesValid(signaturesToExtend);
        signatureRequirementsChecker.assertCertificateChainValidForXLLevel(signatures);

        // Perform signature validation
        // CRITICAL: Fetch NEW validation data for timestamp validation
        // OCSP tokens will be replaced with cached versions in
        // replaceWithCachedOcspTokens()
        ValidationDataContainer validationDataContainer = documentAnalyzer.getValidationData(signatures);

        for (AdvancedSignature signature : signatures) {
            initializeSignatureBuilder((XAdESSignature) signature);
            if (signatureRequirementsChecker.hasALevelOrHigher(signature)) {
                // Unable to extend due to higher levels covering the current XL-level
                continue;
            }

            String indent = removeOldCertificateValues();
            removeOldRevocationValues();
            String timestampIndent = removeLastTimestampAndAnyValidationData();
            if (indent == null) {
                indent = timestampIndent;
            }

            Element levelXUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

            ValidationData aggregatedValidationData = validationDataContainer
                    .getAllValidationDataForSignatureForInclusion(signature);
            ValidationData remainingValidationData = new ValidationData();
            if (aggregatedValidationData != null) {
                remainingValidationData.addValidationData(aggregatedValidationData);
            }

            List<TimestampToken> timestamps = xadesSignature.getAllTimestamps();
            if (Utils.isCollectionNotEmpty(timestamps)) {
                for (TimestampToken timestampToken : timestamps) {
                    ValidationData timestampValidationData = validationDataContainer.getValidationData(timestampToken);
                    if (timestampValidationData == null) {
                        continue;
                    }
                    ValidationData timestampDataCopy = new ValidationData();
                    timestampDataCopy.addValidationData(timestampValidationData);
                    if (timestampDataCopy.isEmpty()) {
                        continue;
                    }

                    remainingValidationData.excludeCertificateTokens(timestampDataCopy.getCertificateTokens());
                    remainingValidationData.excludeCRLTokensCollection(timestampDataCopy.getCrlTokens());
                    remainingValidationData.excludeOCSPTokens(
                            timestampDataCopy.getOcspTokens()
                                    .stream()
                                    .map(Token::getDSSId)
                                    .collect(Collectors.toSet()));

                    appendTimestampValidationDataAfterTimestamp(timestampToken, timestampDataCopy, indent);
                }
            }

            Set<CertificateToken> certificateValuesToAdd = remainingValidationData.getCertificateTokens();
            Set<CRLToken> crlsToAdd = remainingValidationData.getCrlTokens();
            Set<OCSPToken> ocspsToAdd = remainingValidationData.getOcspTokens();

            // CRITICAL: Exclude timestamp signing certificates from the certificate values
            // TSA certificates are already in their respective timestamp tokens
            Set<CertificateToken> filteredCerts = excludeAllTimestampSigningCertificates(
                    certificateValuesToAdd, timestamps);
            
            LOGGER.info("XL-LEVEL: Total certs: {}, After excluding TSA certs: {}", 
                              certificateValuesToAdd.size(), filteredCerts.size());

            // CRITICAL: Replace OCSP tokens with cached ones from C-level to ensure digest
            // matches
            Set<OCSPToken> ocspTokensToEmbed = replaceWithCachedOcspTokens(ocspsToAdd);

            incorporateCertificateValues(unsignedSignaturePropertiesDom, filteredCerts, indent);
            incorporateRevocationValues(unsignedSignaturePropertiesDom, crlsToAdd, ocspTokensToEmbed, indent);

            unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom,
                    levelXUnsignedProperties);
        }

    }

    private void appendTimestampValidationDataAfterTimestamp(TimestampToken timestampToken,
            ValidationData validationData,
            String indent) {
        if (validationData == null || validationData.isEmpty()) {
            return;
        }

        Element timestampElement = locateTimestampElement(timestampToken);
        Element parentElement = unsignedSignaturePropertiesDom;
        String fallbackTimestampId = TIMESTAMP_PREFIX + toXmlIdentifier(timestampToken.getDSSId());
        String effectiveTimestampId = fallbackTimestampId;

        if (timestampElement != null) {
            Node parentNode = timestampElement.getParentNode();
            if (parentNode instanceof Element) {
                parentElement = (Element) parentNode;
            }
            String existingId = timestampElement.getAttribute(XMLDSigAttribute.ID.getAttributeName());
            if (existingId != null && !existingId.isEmpty()) {
                effectiveTimestampId = existingId;
            }
        }

        Element validationDataDom = DomUtils.addElement(documentDom, parentElement,
                getXades141Namespace(), XAdES141Element.TIMESTAMP_VALIDATION_DATA);

        Set<CertificateToken> certificateTokens = validationData.getCertificateTokens();
        Set<CRLToken> crlTokens = validationData.getCrlTokens();
        Set<OCSPToken> ocspTokens = validationData.getOcspTokens();

        // CRITICAL: Exclude timestamp's signing certificate (TSA certificate)
        // It's already included in the timestamp token itself, no need to duplicate
        Set<CertificateToken> certificatesToEmbed = excludeTimestampSigningCertificate(
                certificateTokens, timestampToken);
        
        LOGGER.info("TIMESTAMP-VAL-DATA: Total certs: {}, After excluding TSA cert: {}", 
                          certificateTokens.size(), certificatesToEmbed.size());

        incorporateCertificateValues(validationDataDom, certificatesToEmbed, indent);
        incorporateRevocationValues(validationDataDom, crlTokens, ocspTokens, indent);

        String idSuffix = toXmlIdentifier(timestampToken.getDSSId());
        validationDataDom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), TST_VD_PREFIX + idSuffix);
        validationDataDom.setAttribute("URI", "#" + effectiveTimestampId);

        if (timestampElement != null && timestampElement.getParentNode() == parentElement) {
            Node nextSibling = timestampElement.getNextSibling();
            if (nextSibling != null) {
                parentElement.insertBefore(validationDataDom, nextSibling);
            }
        }

        if (params.isPrettyPrint()) {
            DSSXMLUtils.indentAndReplace(documentDom, validationDataDom);
        }
    }

    private Element locateTimestampElement(TimestampToken timestampToken) {
        byte[] targetEncoded = timestampToken.getEncoded();
        if (targetEncoded == null) {
            return null;
        }

        Element directMatch = locateTimestampElement(unsignedSignaturePropertiesDom, targetEncoded);
        if (directMatch != null) {
            return directMatch;
        }

        Element signatureElement = xadesSignature.getSignatureElement();
        NodeList encapsulatedNodes = signatureElement.getElementsByTagNameNS("*",
                getCurrentXAdESElements().getElementEncapsulatedTimeStamp().getTagName());
        for (int i = 0; i < encapsulatedNodes.getLength(); i++) {
            Node node = encapsulatedNodes.item(i);
            if (!(node instanceof Element)) {
                continue;
            }
            String xmlValue = ((Element) node).getTextContent();
            if (!Utils.isStringNotEmpty(xmlValue)) {
                continue;
            }
            byte[] xmlBytes = Utils.fromBase64(xmlValue);
            if (xmlBytes != null && Arrays.equals(xmlBytes, targetEncoded)) {
                Node parent = node.getParentNode();
                if (parent instanceof Element) {
                    return (Element) parent;
                }
            }
        }
        return null;
    }

    private Element locateTimestampElement(Element parent, byte[] targetEncoded) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (!(node instanceof Element)) {
                continue;
            }
            Element element = (Element) node;
            if (!isTimestampLocalName(element.getLocalName())) {
                continue;
            }
            Element encapsulated = findEncapsulatedTimestamp(element);
            if (encapsulated == null) {
                continue;
            }
            String xmlValue = encapsulated.getTextContent();
            if (!Utils.isStringNotEmpty(xmlValue)) {
                continue;
            }
            byte[] xmlBytes = Utils.fromBase64(xmlValue);
            if (xmlBytes != null && Arrays.equals(xmlBytes, targetEncoded)) {
                return element;
            }
        }
        return null;
    }

    private boolean isTimestampLocalName(String localName) {
        if (localName == null) {
            return false;
        }
        return "SignatureTimeStamp".equals(localName)
                || "SigAndRefsTimeStamp".equals(localName)
                || "SigAndRefsTimeStampV2".equals(localName)
                || "RefsOnlyTimeStamp".equals(localName)
                || "RefsOnlyTimeStampV2".equals(localName)
                || "ArchiveTimeStamp".equals(localName);
    }

    private Element findEncapsulatedTimestamp(Element timestampElement) {
        String encapsulatedTag = getCurrentXAdESElements().getElementEncapsulatedTimeStamp().getTagName();
        NodeList encapsulatedList = timestampElement.getElementsByTagNameNS("*", encapsulatedTag);
        for (int i = 0; i < encapsulatedList.getLength(); i++) {
            Node candidate = encapsulatedList.item(i);
            if (candidate instanceof Element) {
                return (Element) candidate;
            }
        }
        return null;
    }

    private List<AdvancedSignature> getExtendToXLLevelSignatures(List<AdvancedSignature> signatures) {
        final List<AdvancedSignature> signaturesToExtend = new ArrayList<>();
        for (AdvancedSignature signature : signatures) {
            if (xlLevelExtensionRequired(signature)) {
                signaturesToExtend.add(signature);
            }
        }
        return signaturesToExtend;
    }

    private boolean xlLevelExtensionRequired(AdvancedSignature signature) {
        return XAdES_XL.equals(params.getSignatureLevel()) || !signature.hasAProfile();
    }

    /**
     * Excludes all timestamp signing certificates from the certificate set.
     * This processes all timestamps in the signature and removes their TSA certificates.
     * 
     * @param certificates The set of certificates to filter
     * @param timestamps List of all timestamps in the signature
     * @return A new set with all timestamp signing certificates excluded
     */
    private Set<CertificateToken> excludeAllTimestampSigningCertificates(
            Set<CertificateToken> certificates, List<TimestampToken> timestamps) {
        
        if (certificates == null || certificates.isEmpty()) {
            return certificates;
        }
        
        if (timestamps == null || timestamps.isEmpty()) {
            return certificates;
        }
        
        Set<CertificateToken> filteredCerts = new java.util.LinkedHashSet<>(certificates);
        int excludedCount = 0;
        
        try {
            // Collect all timestamp signing certificates
            Set<CertificateToken> tsaCerts = new java.util.HashSet<>();
            
            for (TimestampToken timestamp : timestamps) {
                // Get TSA certificate from timestamp's certificate source
                // The first certificate in the chain is the signing certificate
                if (timestamp.getCertificates() != null && !timestamp.getCertificates().isEmpty()) {
                    CertificateToken tsaCert = timestamp.getCertificates().get(0);
                    tsaCerts.add(tsaCert);
                }
            }
            
            // Remove all TSA certificates from the set
            for (CertificateToken tsaCert : tsaCerts) {
                if (filteredCerts.remove(tsaCert)) {
                    excludedCount++;
                    LOGGER.info("XL-LEVEL: ✂️  Excluded TSA signing certificate: {}", 
                        tsaCert.getSubject().getPrettyPrintRFC2253());
                }
            }
            
            if (excludedCount > 0) {
                LOGGER.info("XL-LEVEL: Excluded {} TSA certificate(s) from CertificateValues", excludedCount);
            }
            
        } catch (Exception e) {
            // If anything fails, return original set (safe fallback)
            LOGGER.error("XL-LEVEL: Failed to exclude TSA certs: {}", e.getMessage());
            e.printStackTrace();
            return certificates;
        }
        
        return filteredCerts;
    }

    /**
     * Excludes the timestamp's signing certificate from the certificate set.
     * The TSA's signing certificate is already embedded in the timestamp token,
     * so it doesn't need to be duplicated in CertificateValues.
     * 
     * @param certificates The set of certificates to filter
     * @param timestampToken The timestamp token containing the signing certificate
     * @return A new set with the timestamp signing certificate excluded
     */
    private Set<CertificateToken> excludeTimestampSigningCertificate(
            Set<CertificateToken> certificates, TimestampToken timestampToken) {
        
        if (certificates == null || certificates.isEmpty()) {
            return certificates;
        }
        
        if (timestampToken == null) {
            return certificates;
        }
        
        try {
            // Get timestamp's signing certificate (TSA certificate)
            // The first certificate in the chain is the signing certificate
            CertificateToken timestampSigningCert = null;
            if (timestampToken.getCertificates() != null && !timestampToken.getCertificates().isEmpty()) {
                timestampSigningCert = timestampToken.getCertificates().get(0);
            }
            
            if (timestampSigningCert == null) {
                LOGGER.info("TIMESTAMP-VAL-DATA: No signing cert found in timestamp, keeping all certs");
                return certificates;
            }
            
            // Create new set without the timestamp signing certificate
            Set<CertificateToken> filteredCerts = new java.util.LinkedHashSet<>();
            
            for (CertificateToken cert : certificates) {
                if (!cert.equals(timestampSigningCert)) {
                    filteredCerts.add(cert);
                } else {
                    LOGGER.info("TIMESTAMP-VAL-DATA: ✂️  Excluded TSA signing certificate: {}", 
                        cert.getSubject().getPrettyPrintRFC2253());
                }
            }
            
            return filteredCerts;
            
        } catch (Exception e) {
            // If anything fails, return original set (safe fallback)
            LOGGER.error("TIMESTAMP-VAL-DATA: Failed to exclude TSA cert: {}", e.getMessage());
            e.printStackTrace();
            return certificates;
        }
    }

    /**
     * Replaces OCSP tokens with cached versions from C-level to ensure digest
     * consistency.
     * Matches by CERTIFICATE (not digest) since same cert gets different OCSP
     * responses over time.
     * 
     * @param newOcspTokens The newly fetched OCSP tokens
     * @return A set of OCSP tokens with cached versions where available
     */
    private Set<OCSPToken> replaceWithCachedOcspTokens(Set<OCSPToken> newOcspTokens) {
        LOGGER.info("=== XL-LEVEL: replaceWithCachedOcspTokens ===");

        if (newOcspTokens == null || newOcspTokens.isEmpty()) {
            LOGGER.info("XL-LEVEL: No new OCSP tokens to process");
            return newOcspTokens;
        }

        // Get signature-specific cache
        java.util.concurrent.ConcurrentHashMap<String, OCSPToken> signatureCache = null;
        if (currentSignatureId != null) {
            signatureCache = ocspCacheBySignature.get(currentSignatureId);
        }

        if (signatureCache == null || signatureCache.isEmpty()) {
            LOGGER.error("XL-LEVEL: ERROR - No cached OCSP tokens available for signature: {}", currentSignatureId);
            LOGGER.error("XL-LEVEL: This will cause 'OCSP not found in references' error!");
            return newOcspTokens;
        }

        LOGGER.info("XL-LEVEL [{}]: Cache has {} OCSP tokens", currentSignatureId, signatureCache.size());
        LOGGER.info("XL-LEVEL: Processing {} new OCSP tokens", newOcspTokens.size());

        Set<OCSPToken> replacedTokens = new java.util.LinkedHashSet<>();
        DigestAlgorithm digestAlgorithm = params.getTokenReferencesDigestAlgorithm();

        int replacedCount = 0;
        int notFoundCount = 0;

        for (OCSPToken newToken : newOcspTokens) {
            try {
                // Get the certificate that this OCSP is validating
                CertificateToken relatedCert = newToken.getRelatedCertificate();

                if (relatedCert == null) {
                    LOGGER.warn("XL-LEVEL: WARNING - OCSP token has no related certificate!");
                    replacedTokens.add(newToken);
                    notFoundCount++;
                    continue;
                }

                String certKey = Utils.toBase64(relatedCert.getEncoded());
                byte[] newOcspDigest = newToken.getDigest(digestAlgorithm);

                LOGGER.info("XL-LEVEL [{}]: Processing OCSP for cert {}", 
                        currentSignatureId, certKey.substring(0, Math.min(20, certKey.length())));
                LOGGER.info("XL-LEVEL: New OCSP digest: {}", 
                        Utils.toBase64(newOcspDigest).substring(0, 20));

                // Check if we have a cached token for this certificate in signature-specific
                // cache
                OCSPToken cachedToken = signatureCache.get(certKey);

                if (cachedToken != null) {
                    // Use cached token - ensures it has a matching OCSPRef from C-level
                    byte[] cachedOcspDigest = cachedToken.getDigest(digestAlgorithm);

                    LOGGER.info("XL-LEVEL: ✅ Found cached OCSP!");
                    LOGGER.info("XL-LEVEL: Cached OCSP digest: {}", 
                            Utils.toBase64(cachedOcspDigest).substring(0, 20));
                    LOGGER.info("XL-LEVEL: Using CACHED token (has OCSPRef)");

                    replacedTokens.add(cachedToken);
                    replacedCount++;
                } else {
                    // No cached version for this certificate - this will cause validation error!
                    LOGGER.error("XL-LEVEL: ❌ ERROR - No cached OCSP for this certificate!");
                    LOGGER.error("XL-LEVEL: This OCSP will have NO OCSPRef!");
                    LOGGER.error("XL-LEVEL: Validation will fail!");

                    replacedTokens.add(newToken);
                    notFoundCount++;
                }
            } catch (Exception e) {
                LOGGER.error("XL-LEVEL: Exception while processing OCSP: {}", e.getMessage());
                e.printStackTrace();
                replacedTokens.add(newToken);
                notFoundCount++;
            }
        }

        LOGGER.info("=== XL-LEVEL SUMMARY ===");
        LOGGER.info("Total OCSP tokens: {}", newOcspTokens.size());
        LOGGER.info("Replaced with cached: {}", replacedCount);
        LOGGER.info("Not found in cache: {}", notFoundCount);
        LOGGER.info("========================");

        return replacedTokens;
    }
}