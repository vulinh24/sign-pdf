package com.pdfsignature.pdf;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Font;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.BaseFont;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.pdfsignature.utils.CryptoToken;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

public class PDFSigner {
    private static final Logger LOG = Logger.getLogger(PDFSigner.class);
    private static final String FONT_DIR = "C:\\Users\\LinhVu\\Desktop\\signpdf\\src\\main\\java\\com\\pdfsignature\\files\\ARLRDBD.TTF";

    private static final String reason = "Personal Document";
    private static final String location = "Owner's company";

    public static byte[] sign(byte[] inputData, CryptoToken token)
            throws Exception {
        byte[] result = null;

        if (inputData == null) {
            LOG.error("SignatureException: " + "data null");
            throw new RuntimeException("data null");
        }

        if (token == null) {
            LOG.error("SignatureException: " + "CryptoToken null");
            throw new Exception("CryptoToken null");
        }

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        // Get and check signer's information
        X509Certificate signerCert = token.getSignerCert();
        if (signerCert == null) {
            LOG.error("SignatureException: " + "Signer certificate null");
            throw new Exception("Signer certificate null");
        }
        PrivateKey pk = token.getPrivateKey();
        if (pk == null) {
            LOG.error("SignatureException: " + "Signer private key null");
            throw new Exception("Signer private key null");
        }
        Certificate[] certChain = new Certificate[1];
        certChain[0] = signerCert;

        // Sign pdf document
        PdfReader reader;
        try {
            reader = new PdfReader(inputData);
        } catch (IOException e1) {
            LOG.error("SignatureException: " + "Cannot load input data or not a pdf file");
            throw new Exception("Cannot load input data", e1);
        }

        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        PdfStamper stamper = null;
        try {
            stamper = PdfStamper.createSignature(reader, outStream, '\0');
        } catch (DocumentException e1) {
            LOG.error("DocumentException: " + e1.getMessage());
            throw new Exception(e1.getMessage(), e1);
        } catch (IOException e1) {
            LOG.error("IOException: " + e1.getMessage());
            throw new Exception(e1.getMessage(), e1);
        }

        // Create signature appearance
        // ---------------------------------------------------------
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setVisibleSignature(new Rectangle(420, 40, 570, 85), 1,
                "Signserver-field");
        appearance.setReason(reason);
        appearance.setLocation(location);

        String author = "";
        LdapName ldap;
        try {
            ldap = new LdapName(signerCert.getSubjectX500Principal().getName());
            for (Rdn rdn : ldap.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    author = rdn.getValue().toString();
                    break;
                }
            }
        } catch (InvalidNameException ignored) {
        }

        // Show visible signature
        Font fnt = null;
        try {
            BaseFont bf = BaseFont.createFont(FONT_DIR, BaseFont.IDENTITY_H,
                    BaseFont.EMBEDDED);
            fnt = new Font(bf, 6);
        } catch (DocumentException e2) {
            LOG.error("DocumentException: " + e2.getMessage());
            throw new Exception(e2.getMessage(), e2);
        } catch (IOException e2) {
            LOG.error("IOException: " + e2.getMessage());
            throw new Exception(e2.getMessage(), e2);
        }

        SimpleDateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
        String singingTime = df.format(new Date());
        String test = "Ký bởi: " + author + "\nKý ngày: " + singingTime;
        appearance.setLayer2Font(fnt);
        appearance.setLayer2Text(test);
        // ---------------------------------------------------------

        // Generate signature
        // ---------------------------------------------------------
        ExternalSignature es = new PrivateKeySignature(pk, "SHA-1",
                provider.getName());
        ExternalDigest digest = new BouncyCastleDigest();
        try {
            MakeSignature.signDetached(appearance, digest, es, certChain, null,
                    null, null, 0, CryptoStandard.CMS);

            result = outStream.toByteArray();
            outStream.close();
        } catch (IOException e) {
            LOG.error("IOException: " + e.getMessage());
            throw new Exception(e.getMessage(), e);
        } catch (DocumentException e) {
            LOG.error("DocumentException: " + e.getMessage());
            throw new Exception(e.getMessage(), e);
        } catch (GeneralSecurityException e) {
            LOG.error("GeneralSecurityException: " + e.getMessage());
            throw new Exception(e.getMessage(), e);
        }

        return result;
    }
}
