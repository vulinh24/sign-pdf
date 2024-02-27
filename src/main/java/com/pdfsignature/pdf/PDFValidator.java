package com.pdfsignature.pdf;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.pdfsignature.utils.CryptoToken;
import com.pdfsignature.utils.FileUtil;
import com.pdfsignature.ValidationError;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

public class PDFValidator {
    final static Logger LOG = Logger.getLogger(PDFValidator.class);

    /**
     * Verify pdf signed data
     *
     * @param signedData byte array signed data
     * @param token
     * @return Verify code
     */
    public static int verify(byte[] signedData, CryptoToken token) {
        X509Certificate issuerSignerCert = token.getSignerCert();
        PdfReader reader = null;
        try {
            reader = new PdfReader(signedData);
            if (!FileUtil.isSigned(signedData))
                return ValidationError.SIGNATURE_NOT_FOUND;
        } catch (IOException e) {
            LOG.error("Cannot load signed data or not a pdf file. " + e.getMessage());
            return ValidationError.CANNOT_LOAD_SIGNED_DATA;
        }

        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();

        for (String name : names) {
            PdfPKCS7 pkcs7 = fields.verifySignature(name);
            boolean signatureValid = false;
            boolean completeDocumentIsSigned = false;
            try {
                signatureValid = pkcs7.verify();
                completeDocumentIsSigned = fields.signatureCoversWholeDocument(name);
            } catch (GeneralSecurityException e) {
                LOG.error("Signature with field name " + name + " is invalid");
            }
            if (!signatureValid || !completeDocumentIsSigned) {
                LOG.error("CONTENT MODIFIED ");
                return ValidationError.SIGNATURE_INVALID;
            }

            Date signingTime = pkcs7.getSignDate().getTime();
            X509Certificate signingCert = pkcs7.getSigningCertificate();

            // verify sign time
            try {
                signingCert.checkValidity(signingTime);
                LOG.info("VALIDITY TIME: DONE");
            } catch (CertificateExpiredException e) {
                LOG.error("VALIDITY: Expired at signing time");
                return -3;
            } catch (CertificateNotYetValidException e) {
                LOG.error("VALIDITY: Not yet valid at signing time");
                return -3;
            }
            //Verify signer's certificate
            verifyIssuerCertificateByPairKey(token, issuerSignerCert, signingCert);

        }
        return ValidationError.SIGNATURE_VALID;
    }

    private static void verifyIssuerCertificateByPairKey(CryptoToken token, X509Certificate issuerSignerCert, X509Certificate signingCert) {
        LOG.info("VERIFY CERTIFICATE: " + signingCert.getSerialNumber() + " - " + signingCert.getSubjectX500Principal());
        final String strToEncrypt = "Hello, World!";

        PrivateKey privateKey = token.getPrivateKey();
        PublicKey publicKey = signingCert.getPublicKey();
        // Sign some data with the private key
        Signature signature = null;
        try {
            signature = Signature.getInstance(issuerSignerCert.getSigAlgName());
            signature.initSign(privateKey);
            byte[] data = strToEncrypt.getBytes();
            signature.update(data);
            byte[] signatureValue = signature.sign();

            // Verify the signature using the public key
            Signature verifier = Signature.getInstance(issuerSignerCert.getSigAlgName());
            verifier.initVerify(publicKey);
            verifier.update(data);
            boolean signatureMatched = verifier.verify(signatureValue);

            System.out.println("Signature matched: " + signatureMatched);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
