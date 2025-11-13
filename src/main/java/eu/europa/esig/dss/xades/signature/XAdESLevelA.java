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

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationData;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import java.util.List;

/**
 * Holds level A aspects of XAdES
 *
 */
public class XAdESLevelA extends XAdESLevelXL {
    private static final Logger LOGGER = LoggerFactory.getLogger(XAdESLevelA.class);

    /**
     * The default constructor for XAdESLevelA.
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * */
    public XAdESLevelA(CertificateVerifier certificateVerifier) {
        super(certificateVerifier);
    }

    /**
     * Adds the ArchiveTimeStamp element which is an unsigned property qualifying the signature. The hash sent to the TSA
     * (messageImprint) is computed on the XAdES-X-L form of the electronic signature and the signed data objects.<br>
     *
     * A XAdES-A form MAY contain several ArchiveTimeStamp elements.
     *
     * @see XAdESLevelXL#extendSignatures(List)
     */
    @Override
    protected void extendSignatures(List<AdvancedSignature> signatures) {
        super.extendSignatures(signatures);

        final SignatureRequirementsChecker signatureRequirementsChecker = getSignatureRequirementsChecker();
        signatureRequirementsChecker.assertSignaturesValid(signatures);

        boolean addTimestampValidationData = false;

        for (AdvancedSignature signature : signatures) {
            initializeSignatureBuilder((XAdESSignature) signature);
            assertExtendSignatureToAPossible();

            if (xadesSignature.hasLTAProfile()) {
                addTimestampValidationData = true;
            }
        }

        // ########################OVERRIDE_DSS#########################
        // ##### Bu override, DSS (Digital Signature Services)         #
        // ##### kütüphanesinin XAdESLevelA'ın imza uzatma             #
        // ##### davranışını projeye özel şekilde değiştirmek/dokümana #
        // ##### uygun müdahale etmek için eklendi.                    #
        // #############################################################
        //
        // Bu alana özel kod eklemek, imzanın C/XL seviyelerinde
        // gömülen OCSP/CRL ve validation cache mekanizmasının
        // a-seviyesinde aynen taşınmasını, yeni bir validation toplama
        // zorlanmasının önüne geçer (ör: Türkiye e-Fatura gibi
        // gereksinimlerde CRL/OCSP doğrulama geçmişini korumak için kritiktir).
        //
        // Bu alan, imza geçerliliği (validation evidence)
        // için cached (önceden toplanmış) verinin A seviyesine
        // doğru şekilde yansıtılmasını sağlar.
        //
        // #############################################################
        
        // Perform signature validation
        // CRITICAL: Reuse cached validation data from C/XL levels
        // This ensures consistency with previously embedded OCSP/CRL references and values
        ValidationDataContainer validationDataContainer = null;
        if (addTimestampValidationData) {
            if (cachedValidationDataContainer != null) {
                // Use cached data from C-level - maintains OCSP/CRL consistency
                validationDataContainer = cachedValidationDataContainer;
                LOGGER.info("A-LEVEL: Using cached validation data from C/XL levels");
            } else {
                // Fallback: fetch new data
                validationDataContainer = documentAnalyzer.getValidationData(signatures);
                LOGGER.warn("A-LEVEL: WARNING - No cached data, fetching new validation data");
            }
        }

        // Append LTA-level (+ ValidationData)
        for (AdvancedSignature signature : signatures) {
            initializeSignatureBuilder((XAdESSignature) signature);
            Element levelXLUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

            if (xadesSignature.hasLTAProfile() && addTimestampValidationData && validationDataContainer != null) {
            // if (xadesSignature.hasLTAProfile() && addTimestampValidationData) {
                // must be executed before data removing
                String indent = removeLastTimestampAndAnyValidationData();

                final ValidationData validationDataForInclusion = validationDataContainer.getAllValidationDataForSignatureForInclusion(signature);
                incorporateTimestampValidationData(validationDataForInclusion, indent);
            }
            incorporateArchiveTimestamp();

            unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelXLUnsignedProperties);
        }
    }

    private void assertExtendSignatureToAPossible() {
        if (SignatureLevel.XAdES_A.equals(params.getSignatureLevel())) {
            assertDetachedDocumentsContainBinaries();
        }
    }

}