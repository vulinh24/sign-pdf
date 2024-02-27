package com.pdfsignature.utils;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;


public class CryptoTokenUtil {
    private static final String PKCS12_KEYSTORE = "PKCS12";

    public static CryptoToken initFromPkcs12(InputStream inStream, String password) throws SignaturesException {
        CryptoToken token = null;
        try {
            KeyStore keystore = KeyStore.getInstance(PKCS12_KEYSTORE);
            keystore.load(inStream, password.toCharArray());

            Enumeration<String> aliases = keystore.aliases();
            if (aliases == null || !aliases.hasMoreElements()) {
                throw new SignaturesException("No key alias was found in keystore");
            }
            String alias = null;

            while (aliases.hasMoreElements()) {
                String currentAlias = aliases.nextElement();
                if (keystore.isKeyEntry(currentAlias)) {
                    alias = currentAlias;
                    break;
                }
            }
            // Throw exception if key entry not be found.
            if (alias == null) {
                throw new SignaturesException("No key entry was found in keystore");
            }

            token = getFromKeystore(keystore, alias, password);
        } catch (KeyStoreException e) {
            throw new SignaturesException("KeyStoreException", e);
        } catch (CertificateException e) {
            throw new SignaturesException("CertificateException", e);
        } catch (NoSuchAlgorithmException e) {
            throw new SignaturesException("NoSuchAlgorithmException", e);
        } catch (IOException e) {
            throw new SignaturesException("IOException", e);
        } catch (UnrecoverableKeyException e) {
            throw new SignaturesException("UnrecoverableKeyException", e);
        }

        return token;
    }

    private static CryptoToken getFromKeystore(KeyStore keystore, String alias,
                                               String password) throws UnrecoverableKeyException,
            KeyStoreException, NoSuchAlgorithmException, CertificateException,
            SignaturesException {
        if (alias == null) {
            throw new SignaturesException("No alias was found in keystore");
        }

        CryptoToken token = null;
        // Get private key from keystore
        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, password.toCharArray());

        // Get signer's certificate and cast to X509Certificate if able
        // Only work with X509Certificate
        Certificate cert = keystore.getCertificate(alias);
        X509Certificate signerCert = null;
        if (cert instanceof X509Certificate) {
            signerCert = (X509Certificate) cert;
        }

        // Get signer's certchain and Issuer's certificate
        // Check issuer's signature on signer's certificate first
        Certificate[] certChain = keystore.getCertificateChain(alias);
        X509Certificate issuerCert = null;
        if (signerCert != null) {
            for (Certificate c : certChain) {
                try {
                    if (c instanceof X509Certificate) {
                        signerCert.verify(c.getPublicKey());
                        issuerCert = (X509Certificate) c;
                        break;
                    }
                } catch (InvalidKeyException | NoSuchProviderException | SignatureException e) {
                    // Do nothing here
                }
            }
        }
        Provider privateProvider = keystore.getProvider();
        token = new CryptoToken(privateKey, signerCert, issuerCert, certChain,
                privateProvider);
        return token;
    }
}
