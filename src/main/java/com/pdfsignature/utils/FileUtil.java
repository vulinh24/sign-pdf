package com.pdfsignature.utils;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.ArrayList;

public class FileUtil {

    /**
     * Read all bytes from file to byte array
     *
     * @param inputPath input file directory
     * @return a byte array
     * @throws IOException when file not found or something else
     */
    public static byte[] readBytesFromFile(String inputPath)
            throws IOException {
        ByteArrayOutputStream ous = null;
        InputStream ios = null;
        try {
            byte[] buffer = new byte[4096];
            ous = new ByteArrayOutputStream();
            ios = Files.newInputStream(new File(inputPath).toPath());
            int read = 0;
            while ((read = ios.read(buffer)) != -1) {
                ous.write(buffer, 0, read);
            }
        } finally {
            try {
                if (ous != null)
                    ous.close();
            } catch (IOException e) {}
            try {
                if (ios != null)
                    ios.close();
            } catch (IOException e) {}
        }
        return ous.toByteArray();
    }

    /**
     * Write byte array to file
     *
     * @param input    byte array file encode
     * @param pathname output file directory
     */
    public static int writeToFile(byte[] input, String pathname) {
        FileOutputStream outStream = null;
        try {
            outStream = new FileOutputStream(pathname);
            outStream.write(input);

            return 0;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return 1;
        } catch (IOException e) {
            e.printStackTrace();
            return 2;
        } finally {
            if (outStream != null) {
                try {
                    outStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static boolean isSigned(byte[] pdfContent) throws IOException {
        boolean signed = false;
        PdfReader reader = new PdfReader(pdfContent);
        AcroFields af = reader.getAcroFields();
        ArrayList signatureNameNames = af.getSignatureNames();
        signed = !(signatureNameNames.size() == 0);
        reader.close();
        return signed;
    }

    public static CryptoToken getCryptoToken(String keystorePath, String keystorePass) throws FileNotFoundException {
        FileInputStream inStream = new FileInputStream(keystorePath);
        CryptoToken token = null;
        try {
            token = CryptoTokenUtil.initFromPkcs12(inStream, keystorePass);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return token;
    }
}
