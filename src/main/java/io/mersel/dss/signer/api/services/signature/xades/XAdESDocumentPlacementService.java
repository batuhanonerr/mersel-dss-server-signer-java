package io.mersel.dss.signer.api.services.signature.xades;

import io.mersel.dss.signer.api.constants.XmlConstants;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * XML belgelerinde imza elemanlarını yerleştiren servis.
 * Belge tipine özgü yerleştirme mantığını yönetir (UBL, e-Arşiv, HrXml vb.).
 */
@Service
public class XAdESDocumentPlacementService {

    /**
     * İmza elemanını belge tipine göre uygun konuma yerleştirir.
     * 
     * @param document Ana XML belgesi
     * @param signatureElement Yerleştirilecek imza elemanı
     * @param documentType Belge tipi
     */
    public void placeSignatureElement(Document document, 
                                     Element signatureElement,
                                     DocumentType documentType) {
        // İmzayı mevcut üst elemanından kaldır
        Node parent = signatureElement.getParentNode();
        if (parent != null) {
            parent.removeChild(signatureElement);
        }

        // Belge tipine göre hedef konumu belirle
        Node target = resolveTargetNode(document, documentType);

        // İmzayı import et ve ekle
        Node importedSignature = document.importNode(signatureElement, true);
        target.appendChild(importedSignature);
    }

    /**
     * İmzanın yerleştirileceği hedef node'u çözümler.
     */
    private Node resolveTargetNode(Document document, DocumentType documentType) {
        Node target = null;

        switch (documentType) {
            case UblDocument:
                target = findUblExtensionContent(document);
                break;
                
            case EArchiveReport:
                target = findEArchiveHeader(document);
                break;
                
            case HrXml:
                target = findHrXmlSignatureContainer(document);
                break;
                
            default:
                // Diğer belge tipleri için kök elemana yerleştir
                break;
        }

        // Yedek olarak belge köküne yerleştir
        if (target == null) {
            target = document.getDocumentElement();
        }

        return target;
    }

    /**
     * UBL ExtensionContent elemanını bulur. Yoksa UBLExtensions/UBLExtension/ExtensionContent
     * yapısını kök elemanın başına ekleyip ExtensionContent döner.
     */
    private Node findUblExtensionContent(Document document) {
        Node target = getFirstElementByTagNameNS(document, XmlConstants.NS_UBL_EXTENSION, "ExtensionContent");
        if (target != null) {
            return target;
        }

        Element root = document.getDocumentElement();
        Element ublExtensions = document.createElementNS(XmlConstants.NS_UBL_EXTENSION, "UBLExtensions");
        Element ublExtension = document.createElementNS(XmlConstants.NS_UBL_EXTENSION, "UBLExtension");
        Element extensionContent = document.createElementNS(XmlConstants.NS_UBL_EXTENSION, "ExtensionContent");

        ublExtension.appendChild(extensionContent);
        ublExtensions.appendChild(ublExtension);

        Node firstChild = root.getFirstChild();
        if (firstChild != null) {
            root.insertBefore(ublExtensions, firstChild);
        } else {
            root.appendChild(ublExtensions);
        }

        return extensionContent;
    }

    /**
     * e-Arşiv Raporu başlık elemanını bulur.
     * 
     * @throws IllegalArgumentException Başlık elemanı bulunamazsa
     */
    private Node findEArchiveHeader(Document document) {
        Node target = getFirstElementByTagNameNS(document, XmlConstants.NS_EARSIV, "baslik");
        
        if (target == null) {
            throw new IllegalArgumentException(
                String.format("e-Arşiv rapor belgesi için 'baslik' elemanı bulunamadı. " +
                             "Beklenen namespace: %s", XmlConstants.NS_EARSIV));
        }
        
        return target;
    }

    /**
     * HrXml imza konteynırını bulur.
     * 
     * @throws IllegalArgumentException ApplicationArea elemanı bulunamazsa
     */
    private Node findHrXmlSignatureContainer(Document document) {
        // ApplicationArea'yı namespace ile bul
        Node applicationArea = getFirstElementByTagNameNS(document, XmlConstants.NS_OAGIS, "ApplicationArea");
        
        // Namespace olmadan fallback
        if (applicationArea == null) {
            applicationArea = getFirstElementByTagName(document, "ApplicationArea");
        }
        
        if (applicationArea == null) {
            throw new IllegalArgumentException(
                String.format("HrXml belgesi için 'ApplicationArea' elemanı bulunamadı. " +
                             "Beklenen namespace: %s", XmlConstants.NS_OAGIS));
        }

        // ApplicationArea içinde Signature node'unu bul (namespace ile)
        Node signatureNode = getFirstChildElementNS(applicationArea, XmlConstants.NS_OAGIS, "Signature");
        
        // Namespace olmadan fallback
        if (signatureNode == null) {
            signatureNode = getFirstChildElement(applicationArea, "Signature");
        }
        
        return signatureNode != null ? signatureNode : applicationArea;
    }

    private Node getFirstElementByTagName(Document document, String tagName) {
        NodeList nodeList = document.getElementsByTagName(tagName);
        return (nodeList != null && nodeList.getLength() > 0) ? nodeList.item(0) : null;
    }

    private Node getFirstElementByTagNameNS(Document document, String namespace, String localName) {
        NodeList nodeList = document.getElementsByTagNameNS(namespace, localName);
        return (nodeList != null && nodeList.getLength() > 0) ? nodeList.item(0) : null;
    }

    private Node getFirstChildElement(Node parent, String tagName) {
        NodeList nodeList = ((Element) parent).getElementsByTagName(tagName);
        return (nodeList != null && nodeList.getLength() > 0) ? nodeList.item(0) : null;
    }

    private Node getFirstChildElementNS(Node parent, String namespace, String localName) {
        NodeList nodeList = ((Element) parent).getElementsByTagNameNS(namespace, localName);
        return (nodeList != null && nodeList.getLength() > 0) ? nodeList.item(0) : null;
    }
}

