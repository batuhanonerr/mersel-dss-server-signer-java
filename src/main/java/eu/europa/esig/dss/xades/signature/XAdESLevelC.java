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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationData;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xades.definition.xades141.XAdES141Element;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.xml.datatype.XMLGregorianCalendar;

import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_C;
import static eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_XL;

/**
 * Contains XAdES-C profile aspects
 *
 */
public class XAdESLevelC extends XAdESLevelBaselineT {
    private static final Logger LOGGER = LoggerFactory.getLogger(XAdESLevelC.class);

    // ################ BLOK BAŞLANGICI (XADES-C,XL GELİŞMELERİ) ################
    // DSS-XAdES-C seviye geliştirmeleri için dokümantasyon:
    // - OCSP ve CRL doğrulama nesneleri thread-safe olarak ve imza başına özgü olarak cache'lenir.
    // - C seviyesi (referans oluşturma) ve XL seviyesi (bileşen gömme) için aynı doğrulama verisi yeniden kullanılır.
    // - Tüm detaylar ve örnek iş akışları teknik dokümantasyonda açıklanmıştır.
    
    // ########################OVERRIDE_DSS#########################
    // ##### Bu alan, DSS kütüphanesinin XAdES-C seviyesindeki    #
    // ##### gelişmelerimizi özetler.                             #
    // ##### Tam teknik detaylar dökümantasyonda ayrıca verilecek.#
    // #############################################################
    //
    // DSS kütüphanesi XAdES-C seviyesinde, hem revokasyon verileri
    // referanslarının (OCSP/CRL), hem de önbellek/cache yönetiminin
    // doğru ve tutarlı şekilde kullanılması hedeflenmiştir.
    //
    // Bu kapsamda;
    // - OCSP ve CRL token'ları thread-safe ve imzaya özel olarak cache'lenmektedir.
    // - Aynı veriler, hem referans oluştururken (C seviyesi) hem de gömülü veri eklerken 
    //   (XL seviyesi) tekrar kullanılmaktadır.
    // - Bu sayede OCSP/CRL digest eşleşmezliği ve tutarsızlıklar engellenir.
    //
    // Dökümanda ayrıntılı işleyiş ve örnek akışlar yer almaktadır.
    // #############################################################


    /**
     * Cached validation data container to ensure consistency across signature
     * levels (C, XL, A).
     * This prevents OCSP/CRL digest mismatches between references (C-level) and
     * embedded values (XL-level).
     * 
     * The same OCSP/CRL responses must be used when:
     * - Creating references with digests at C-level
     * - Embedding actual response binaries at XL-level
     */
    protected ValidationDataContainer cachedValidationDataContainer;

    /**
     * Thread-safe, signature-specific cache for OCSP tokens.
     * Outer Map: Signature ID -> Inner cache
     * Inner Map: Certificate (base64) -> OCSPToken
     * 
     * This ensures:
     * 1. Thread-safety for concurrent signature operations
     * 2. Cache isolation between different signatures
     * 3. No cache pollution between requests
     */
    protected static final java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.ConcurrentHashMap<String, OCSPToken>> ocspCacheBySignature = new java.util.concurrent.ConcurrentHashMap<>();

    /**
     * Current signature ID being processed (for cache lookup)
     */
    protected String currentSignatureId;
    // ################ BLOK BİTTİ (XADES-C,XL GELİŞMELERİ) ################

    /**
     * The default constructor for XAdESLevelC.
     *
     * @param certificateVerifier {@link CertificateVerifier}
     */
    public XAdESLevelC(CertificateVerifier certificateVerifier) {
        super(certificateVerifier);
    }

    /**
     * This format builds up taking XAdES-T signature and incorporating additional data required for validation:
     *
     * The sequence of references to the full set of CA certificates that have been used to validate the electronic
     * signature up to (but not including ) the signer's certificate.<br>
     * A full set of references to the revocation data that have been used in the validation of the signer and CA
     * certificates.<br>
     * Adds {@code <CompleteCertificateRefs>} and {@code <CompleteRevocationRefs>} segments into
     * {@code <UnsignedSignatureProperties>} element.
     *
     * There SHALL be at most <b>one occurrence of CompleteRevocationRefs and CompleteCertificateRefs</b> properties in
     * the signature. Old references must be removed.
     *
     * @see XAdESLevelBaselineT#extendSignatures(List)
     */
    @Override
    protected void extendSignatures(List<AdvancedSignature> signatures) {
        super.extendSignatures(signatures);

        final List<AdvancedSignature> signaturesToExtend = getExtendToCLevelSignatures(signatures);
        if (Utils.isCollectionEmpty(signaturesToExtend)) {
            return;
        }

        // ################ BLOK BAŞLANGICI (XADES-C,XL GELİŞMELERİ) ################
        // ########################OVERRIDE_DSS#########################
        // ##### Bu alan, XAdES-C seviyesinde imza için gerekli      #
        // ##### doğrulama ve revocation verilerinin hazırlanması.   #
        // ##### Thread-safe cache kullanımı ve tutarlılık sağlanır. #
        // #############################################################
        //
        // XAdES-C seviyesi, zaman damgası (T) sonrası ek doğrulama
        // gereksinimlerini karşılar. Bu aşamada:
        //
        // 1. CompleteCertificateRefs ve CompleteRevocationRefs
        //    öğeleri UnsignedSignatureProperties içine eklenir.
        //
        // 2. OCSP/CRL yanıtları bu aşamada elde edilir ve
        //    imza-özel (signature-specific) cache'te saklanır.
        //
        // 3. Cache kullanımı sayesinde, aynı revocation verileri
        //    hem C seviyesinde (referans) hem de XL seviyesinde
        //    (gömülü değer) tutarlı şekilde kullanılır.
        //
        // 4. Thread-safe ConcurrentHashMap ile eş zamanlı işlemler
        //    izole edilir ve cache kirliliği engellenir.
        //
        // Bu sayede OCSP/CRL digest eşleşmezliği önlenir ve
        // imza arşiv seviyelerine (XL, A) sorunsuz geçiş sağlanır.
        // #############################################################

        // Initialize signature-specific cache context
        if (!signaturesToExtend.isEmpty()) {
            AdvancedSignature firstSignature = signaturesToExtend.get(0);
            currentSignatureId = firstSignature.getId();
            if (currentSignatureId == null || currentSignatureId.isEmpty()) {
                currentSignatureId = "sig_" + System.currentTimeMillis() + "_"
                        + System.identityHashCode(firstSignature);
            }

            // Initialize cache for this signature if not exists
            ocspCacheBySignature.putIfAbsent(currentSignatureId, new java.util.concurrent.ConcurrentHashMap<>());
        }
        // ################ BLOK BİTTİ (XADES-C,XL GELİŞMELERİ) ################        

        // Reset sources
        for (AdvancedSignature signature : signaturesToExtend) {
            initializeSignatureBuilder((XAdESSignature) signature);

            // Data sources can already be loaded in memory (force reload)
            xadesSignature.resetCertificateSource();
            xadesSignature.resetRevocationSources();
            xadesSignature.resetTimestampSource();
        }

        final SignatureRequirementsChecker signatureRequirementsChecker = getSignatureRequirementsChecker();
        if (XAdES_C.equals(params.getSignatureLevel())) {
            signatureRequirementsChecker.assertExtendToCLevelPossible(signaturesToExtend);
        }
        signatureRequirementsChecker.assertSignaturesValid(signaturesToExtend);
        signatureRequirementsChecker.assertCertificateChainValidForCLevel(signaturesToExtend);

        
        // ################ BLOK BAŞLANGICI (XADES-C,XL GELİŞMELERİ) ################
        // CRITICAL: Cache validation data for reuse in XL and A levels
        // This ensures the same OCSP/CRL responses are used across all levels
        ValidationDataContainer validationDataContainer;
        if (cachedValidationDataContainer == null) {
            // First call: Fetch fresh validation data from OCSP/CRL sources
            validationDataContainer = documentAnalyzer.getValidationData(signaturesToExtend);
            // Cache it for subsequent levels (XL, A)
            cachedValidationDataContainer = validationDataContainer;
        } else {
            // Reuse cached data (should not happen in C-level, but safe fallback)
            validationDataContainer = cachedValidationDataContainer;
        }
        // #############################################################

        // Append ValidationData
        for (AdvancedSignature signature : signaturesToExtend) {
            initializeSignatureBuilder((XAdESSignature) signature);
            if (signatureRequirementsChecker.hasXLevelOrHigher(signature)) {
                // Unable to extend due to higher levels covering the current C-level
                continue;
            }

            String indent = removeOldCertificateRefs();
            removeOldRevocationRefs();

            ValidationData validationDataForInclusion = getValidationDataForCLevelInclusion(validationDataContainer, signature);

            Element levelTUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

            // XAdES-C: complete certificate references
            // <xades:CompleteCertificateRefs>
            // ...<xades:CertRefs>
            // ......<xades:Cert>
            // .........<xades:CertDigest>
            incorporateCertificateRefs(unsignedSignaturePropertiesDom, validationDataForInclusion.getCertificateTokens(), indent);

            // XAdES-C: complete revocation references
            // <xades:CompleteRevocationRefs>
            if (Utils.isCollectionNotEmpty(validationDataForInclusion.getCrlTokens()) ||
                    Utils.isCollectionNotEmpty(validationDataForInclusion.getOcspTokens())) {
                final Element completeRevocationRefsDom = DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom,
                        getXadesNamespace(), getCurrentXAdESElements().getElementCompleteRevocationRefs());
                incorporateCRLRefs(completeRevocationRefsDom, validationDataForInclusion.getCrlTokens());
                incorporateOCSPRefs(completeRevocationRefsDom, validationDataForInclusion.getOcspTokens());
            }

            unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelTUnsignedProperties);
        }

    }

    private List<AdvancedSignature> getExtendToCLevelSignatures(List<AdvancedSignature> signatures) {
        final List<AdvancedSignature> signaturesToExtend = new ArrayList<>();
        for (AdvancedSignature signature : signatures) {
            if (cLevelExtensionRequired(signature)) {
                signaturesToExtend.add(signature);
            }
        }
        return signaturesToExtend;
    }

    private boolean cLevelExtensionRequired(AdvancedSignature signature) {
        return XAdES_C.equals(params.getSignatureLevel()) || XAdES_XL.equals(params.getSignatureLevel()) ||
                !signature.hasXProfile();
    }

    private String removeOldCertificateRefs() {
        String text = null;
        final Element certRefs = DomUtils.getElement(xadesSignature.getSignatureElement(), xadesPath.getCompleteCertificateRefsPath());
        final Element certRefsV2 = DomUtils.getElement(xadesSignature.getSignatureElement(), xadesPath.getCompleteCertificateRefsV2Path());
        if (certRefs != null || certRefsV2 != null) {
            text = removeNode(certRefs);
            if (text == null || certRefsV2 != null) {
                text = removeNode(certRefsV2);
            }
            /* Because the element was removed, the certificate source needs to be reset */
            xadesSignature.resetCertificateSource();
        }
        return text;
    }

    private void removeOldRevocationRefs() {
        final Element toRemove = DomUtils.getElement(xadesSignature.getSignatureElement(), xadesPath.getCompleteRevocationRefsPath());
        if (toRemove != null) {
            removeNode(toRemove);
            /* Because the element was removed, the revocation sources need to be reset */
            xadesSignature.resetRevocationSources();
        }
    }

    private void incorporateCertificateRefs(Element parentDom, Collection<CertificateToken> certificatesToBeAdded,
                                            String indent) {
        // TODO : review indent usage
        if (Utils.isCollectionNotEmpty(certificatesToBeAdded)) {
            final Element completeCertificateRefsDom = createCompleteCertificateRefsDom(parentDom);
            final Element certRefsDom = createCertRefsDom(completeCertificateRefsDom);

            DigestAlgorithm tokenReferencesDigestAlgorithm = params.getTokenReferencesDigestAlgorithm();
            for (final CertificateToken certificateToken : certificatesToBeAdded) {
                incorporateCert(certRefsDom, certificateToken, tokenReferencesDigestAlgorithm);
            }
        }

    }

    private Element createCompleteCertificateRefsDom(Element parentDom) {
        if (params.isEn319132()) {
            return DomUtils.addElement(documentDom, parentDom, getXades141Namespace(),
                    XAdES141Element.COMPLETE_CERTIFICATE_REFS_V2);
        } else {
            return DomUtils.addElement(documentDom, parentDom, getXadesNamespace(),
                    getCurrentXAdESElements().getElementCompleteCertificateRefs());
        }
    }

    private Element createCertRefsDom(Element parentDom) {
        if (params.isEn319132()) {
            return DomUtils.addElement(documentDom, parentDom, getXades141Namespace(),
                    XAdES141Element.CERT_REFS);
        } else {
            return DomUtils.addElement(documentDom, parentDom, getXadesNamespace(),
                    getCurrentXAdESElements().getElementCertRefs());
        }
    }

    private ValidationData getValidationDataForCLevelInclusion(final ValidationDataContainer validationDataContainer,
                                                               final AdvancedSignature signature) {
        // Zaman damgası doğrulama verileri artık ayrı bir alanda tutulduğu için buradan siliniyor.
        // Diğer düzenlemelerle uyumlu olması amacıyla bu alandan kaldırılmıştır.

        signature.getSignatureTimestamps().clear();

        ValidationData validationData = validationDataContainer.getAllValidationDataForSignature(signature);
        validationData.excludeCertificateTokens(getCertificateTokensForExclusion());
        return validationData;
    }

    private Collection<CertificateToken> getCertificateTokensForExclusion() {
        /*
         * A.1.1 The CompleteCertificateRefsV2 qualifying property
         *
         * The CompleteCertificateRefsV2 qualifying property:
         * ...
         * 2) Shall not contain the reference to the signing certificate.
         * ...
         */
        CertificateToken signingCertificateToken = xadesSignature.getSigningCertificateToken();
        if (signingCertificateToken != null) {
            return Collections.singletonList(signingCertificateToken);
        }
        return Collections.emptyList();
    }

    /**
     * This method incorporates CRL References like
     *
     * <pre>
     * {@code
     *	 <xades:CRLRefs>
     *	 	<xades:CRLRef>
     *			<xades:DigestAlgAndValue>
     *				<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
     *				<ds:DigestValue>G+z+DaZ6X44wEOueVYvZGmTh4dBkjjctKxcJYEV4HmU=</ds:DigestValue>
     *			</xades:DigestAlgAndValue>
     *			<xades:CRLIdentifier URI="LevelACAOK.crl">
     *				<xades:Issuer>CN=LevelACAOK,OU=Plugtests_STF-428_2011-2012,O=ETSI,C=FR</xades:Issuer>
     *				<xades:IssueTime>2012-03-13T13:58:28.000-03:00</xades:IssueTime>
     *			<xades:Number>4415260066222</xades:Number>
     * }
     * </pre>
     *
     * @param completeRevocationRefsDom {@link Element} "CompleteRevocationRefs"
     * @param crlTokens a collection of {@link CRLToken}s to add
     */
    private void incorporateCRLRefs(Element completeRevocationRefsDom,
                                    Collection<CRLToken> crlTokens) {
        if (crlTokens.isEmpty()) {
            return;
        }

        final Element crlRefsDom = DomUtils.addElement(documentDom, completeRevocationRefsDom, getXadesNamespace(), getCurrentXAdESElements().getElementCRLRefs());

        for (final CRLToken crlToken : crlTokens) {

            final Element crlRefDom = DomUtils.addElement(documentDom, crlRefsDom, getXadesNamespace(), getCurrentXAdESElements().getElementCRLRef());

            DigestAlgorithm digestAlgorithm = params.getTokenReferencesDigestAlgorithm();
            final Element digestAlgAndValueDom = DomUtils.addElement(documentDom, crlRefDom, getXadesNamespace(),
                    getCurrentXAdESElements().getElementDigestAlgAndValue());
            incorporateDigestMethod(digestAlgAndValueDom, digestAlgorithm);
            incorporateDigestValue(digestAlgAndValueDom, digestAlgorithm, crlToken);

            final Element crlIdentifierDom = DomUtils.addElement(documentDom, crlRefDom, getXadesNamespace(), getCurrentXAdESElements().getElementCRLIdentifier());
            // crlIdentifierDom.setAttribute("URI",".crl");
            final String issuerX500PrincipalName = crlToken.getIssuerX500Principal().getName();
            DomUtils.addTextElement(documentDom, crlIdentifierDom, getXadesNamespace(), getCurrentXAdESElements().getElementIssuer(), issuerX500PrincipalName);

            final Date thisUpdate = crlToken.getThisUpdate();
            XMLGregorianCalendar xmlGregorianCalendar = DomUtils.createXMLGregorianCalendar(thisUpdate);
            final String thisUpdateAsXmlFormat = xmlGregorianCalendar.toXMLFormat();
            DomUtils.addTextElement(documentDom, crlIdentifierDom, getXadesNamespace(), getCurrentXAdESElements().getElementIssueTime(), thisUpdateAsXmlFormat);

            // DSSXMLUtils.addTextElement(documentDom, crlRefDom, XAdESNamespaces.XAdES, "xades:Number", ???);

            // ######################## OVERRIDE_DSS #########################
            //  Bu alan orijinal DSS kütüphanesinde eklenmemiştir, üstteki DSS'nin kaynak kodundaki
            //  yorumda da görülebileceği gibi <xades:Number> etiketi atlanmaktadır.
            //  Ancak IMZAGER gibi bazı doğrulayıcılar CRL Number içermeyen imza referanslarını
            //  geçerli saymamaktadır. Bu nedenle, aşağıda ilgili kodda CRL Number (xades:Number)
            //  etiketi dahil edilmiştir.
            //  Benzer bir konu için DSS projesine PR gönderilmiştir:
            //  https://github.com/esig/dss/pull/187
            //  Kalıcı çözüm resmi yayınlanana kadar bu satırlar override olarak çerçevemizde tutulacaktır.
            //  (NOT: Bu bir override değildir; eksik davranışın tamamlanmasıdır.)


            try {
                X509CRL x509CRL = (X509CRL) CertificateFactory.getInstance("X.509")
                        .generateCRL(crlToken.getCRLStream());
                String crlNumber = XadesUtil.extractCrlNumber(x509CRL);
                DomUtils.addTextElement(documentDom, crlIdentifierDom, getXadesNamespace(),
                        getCurrentXAdESElements().getElementNumber(), crlNumber);
            } catch (Exception ignored) {
            }

        }
    }


    /**
     * This method adds OCSP References like :
     *
     * <pre>
     * {@code
     * 	<xades:CRLRefs/>
     *	<xades:OCSPRefs>
     *		<xades:OCSPRef>
     *			<xades:OCSPIdentifier>
     *				<xades:ResponderID>
     *					<xades:ByName>C=AA,O=DSS,CN=OCSP A</xades:ByName>
     *				</xades:ResponderID>
     *				<xades:ProducedAt>2013-11-25T12:33:34.000+01:00</xades:ProducedAt>
     *			</xades:OCSPIdentifier>
     *			<xades:DigestAlgAndValue>
     *				<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
     *				<ds:DigestValue>O1uHdchN+zFzbGrBg2FP3/idD0k=</ds:DigestValue>
     *				...
     *}
     * </pre>
     *
     * @param completeRevocationRefsDom {@link Element} "CompleteRevocationRefs"
     * @param ocspTokens a collection of {@link OCSPToken}s to add
     */
    private void incorporateOCSPRefs(Element completeRevocationRefsDom,
                                     Collection<OCSPToken> ocspTokens) {
        if (ocspTokens.isEmpty()) {
            return;
        }

        final Element ocspRefsDom = DomUtils.addElement(documentDom, completeRevocationRefsDom, getXadesNamespace(), getCurrentXAdESElements().getElementOCSPRefs());

        for (OCSPToken ocspToken : ocspTokens) {

            BasicOCSPResp basicOcspResp = ocspToken.getBasicOCSPResp();
            if (basicOcspResp != null) {

                final Element ocspRefDom = DomUtils.addElement(documentDom, ocspRefsDom, getXadesNamespace(), getCurrentXAdESElements().getElementOCSPRef());

                final Element ocspIdentifierDom = DomUtils.addElement(documentDom, ocspRefDom,
                        getXadesNamespace(), getCurrentXAdESElements().getElementOCSPIdentifier());
                final Element responderIDDom = DomUtils.addElement(documentDom, ocspIdentifierDom,
                        getXadesNamespace(), getCurrentXAdESElements().getElementResponderID());

                final RespID respID = basicOcspResp.getResponderId();
                final ResponderId responderId = DSSRevocationUtils.getDSSResponderId(respID);

                if (responderId.getX500Principal() != null) {
                    DomUtils.addTextElement(documentDom, responderIDDom, getXadesNamespace(),
                            getCurrentXAdESElements().getElementByName(), responderId.getX500Principal().toString());
                } else {
                    final String base64EncodedKeyHashOctetStringBytes = Utils.toBase64(responderId.getSki());
                    DomUtils.addTextElement(documentDom, responderIDDom, getXadesNamespace(),
                            getCurrentXAdESElements().getElementByKey(), base64EncodedKeyHashOctetStringBytes);
                }

                final Date producedAt = basicOcspResp.getProducedAt();
                final XMLGregorianCalendar xmlGregorianCalendar = DomUtils.createXMLGregorianCalendar(producedAt);
                final String producedAtXmlEncoded = xmlGregorianCalendar.toXMLFormat();
                DomUtils.addTextElement(documentDom, ocspIdentifierDom, getXadesNamespace(),
                        getCurrentXAdESElements().getElementProducedAt(), producedAtXmlEncoded);

                DigestAlgorithm digestAlgorithm = params.getTokenReferencesDigestAlgorithm();
                final Element digestAlgAndValueDom = DomUtils.addElement(documentDom, ocspRefDom, getXadesNamespace(),
                        getCurrentXAdESElements().getElementDigestAlgAndValue());
                incorporateDigestMethod(digestAlgAndValueDom, digestAlgorithm);
                incorporateDigestValue(digestAlgAndValueDom, digestAlgorithm, ocspToken);

                // ################ BLOK BAŞLANGICI (OCSP CACHE) ################
                // ########################OVERRIDE_DSS#########################
                // ##### Bu alan, OCSP token'larının C-seviyesinde           #
                // ##### cache'lenerek XL-seviyesinde tekrar kullanımını     #
                // ##### sağlar. Digest eşleşmezliği engellenir.             #
                // #############################################################
                //
                // DSS kütüphanesinin orijinal kodunda, OCSP token'ları
                // C-seviyesinde (referans) ve XL-seviyesinde (gömülü değer)
                // iki kez ayrı olarak çekilmektedir. Bu durum, OCSP
                // yanıtlarının dinamik doğası nedeniyle digest uyumsuzluğuna
                // yol açmaktadır.
                //
                // Çözüm olarak:
                // 1. Her OCSP token, ilgili sertifikanın Base64 anahtarı
                //    ile imza-özel (signature-specific) cache'te saklanır.
                //
                // 2. XL-seviyesinde aynı sertifika için OCSP gerektiğinde,
                //    cache'ten alınarak tutarlılık garanti edilir.
                //
                // 3. Thread-safe ConcurrentHashMap kullanımı ile eş zamanlı
                //    işlemler güvenli şekilde izole edilir.
                //
                // 4. Cache, imza işlemi tamamlandıktan sonra temizlenir.
                //
                // Bu sayede OCSPRef digest'i ile EncapsulatedOCSPValue
                // digest'i her zaman eşleşir ve XAdES-A doğrulaması başarılı olur.
                // #############################################################
                
                try {
                    if (currentSignatureId != null) {
                        CertificateToken relatedCert = ocspToken.getRelatedCertificate();
                        if (relatedCert != null) {
                            String certKey = Utils.toBase64(relatedCert.getEncoded());

                            // Get signature-specific cache
                            java.util.concurrent.ConcurrentHashMap<String, OCSPToken> signatureCache = ocspCacheBySignature
                                    .get(currentSignatureId);

                            if (signatureCache != null) {
                                signatureCache.put(certKey, ocspToken);

                                // Also store digest for debugging
                                byte[] ocspDigest = ocspToken.getDigest(digestAlgorithm);
                                LOGGER.info("C-LEVEL [{}]: Cached OCSP for cert {} with digest {}", 
                                        currentSignatureId, 
                                        certKey.substring(0, Math.min(20, certKey.length())),
                                        Utils.toBase64(ocspDigest).substring(0, 20));
                            }
                        }
                    }
                } catch (Exception e) {
                    LOGGER.error("C-LEVEL: Failed to cache OCSP token: {}", e.getMessage());
                    e.printStackTrace();
                    throw e;
                }
                // ################ BLOK BİTTİ (OCSP CACHE) ################
            }
        }
    }

    // ################ BLOK BAŞLANGICI (CACHE CLEANUP) ################
    // ########################OVERRIDE_DSS#########################
    // ##### Bu alan, OCSP cache temizliği için eklenen           #
    // ##### yardımcı metodları içerir. Memory leak önlenir.      #
    // ##### DSS orijinalinde bulunmayan ek fonksiyonlardır.      #
    // #############################################################
    //
    // DSS kütüphanesinde OCSP cache mekanizması olmadığı için
    // cache temizliği de yoktur. Bizim eklediğimiz cache
    // yapısının memory leak'e yol açmaması için bu metodlar
    // geliştirilmiştir.
    //
    // İki tür temizleme sağlanır:
    //
    // 1. cleanupOcspCache(signatureId):
    //    Belirli bir imza işlemi tamamlandığında, o imzaya
    //    özel cache'in hemen silinmesini sağlar. SignService'de
    //    her imza işlemi sonrası finally bloğunda çağrılır.
    //
    // 2. cleanupOldCaches(maxAgeMillis):
    //    Eğer bir nedenle (exception, crash vb.) cleanup
    //    çağrılmamışsa, eski cache'leri periyodik olarak
    //    temizler. Güvenlik ağı (fallback) görevi görür.
    //
    // Thread-safe: ConcurrentHashMap kullanımı sayesinde
    // eş zamanlı temizleme işlemleri güvenlidir.
    //
    // Kullanım:
    // - Her imza sonrası: cleanupOcspCache(signatureId)
    // - Periyodik: cleanupOldCaches(5 * 60 * 1000L) // 5 dakika
    // #############################################################

    /**
     * Cleans up the OCSP cache for a specific signature.
     * Should be called after signature extension is complete.
     * Thread-safe operation.
     * 
     * @param signatureId The signature ID to clean up
     */
    public static void cleanupOcspCache(String signatureId) {
        if (signatureId != null) {
            java.util.concurrent.ConcurrentHashMap<String, OCSPToken> removed = ocspCacheBySignature
                    .remove(signatureId);
            if (removed != null) {
                LOGGER.info("🧹 Cleaned up OCSP cache for signature: {} (removed {} entries)", 
                        signatureId, removed.size());
            }
        }
    }

    /**
     * Cleans up all OCSP caches older than the specified age.
     * Useful for preventing memory leaks if cleanup wasn't called explicitly.
     * Thread-safe operation.
     * 
     * @param maxAgeMillis Maximum age in milliseconds
     */
    public static void cleanupOldCaches(long maxAgeMillis) {
        long cutoffTime = System.currentTimeMillis() - maxAgeMillis;
        int removedCount = 0;

        for (String signatureId : ocspCacheBySignature.keySet()) {
            // Extract timestamp from signature ID if it follows our format
            if (signatureId.startsWith("sig_")) {
                try {
                    String[] parts = signatureId.split("_");
                    if (parts.length >= 2) {
                        long timestamp = Long.parseLong(parts[1]);
                        if (timestamp < cutoffTime) {
                            ocspCacheBySignature.remove(signatureId);
                            removedCount++;
                        }
                    }
                } catch (NumberFormatException ignored) {
                    // Skip if timestamp can't be parsed
                }
            }
        }

        if (removedCount > 0) {
            LOGGER.info("🧹 Cleaned up {} old OCSP cache(s)", removedCount);
        }
    }
    // ################ BLOK BİTTİ (CACHE CLEANUP) ################
}