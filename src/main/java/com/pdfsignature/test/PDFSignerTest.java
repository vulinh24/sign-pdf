package com.pdfsignature.test;

import com.pdfsignature.pdf.PDFSigner;
import com.pdfsignature.utils.CryptoToken;
import com.pdfsignature.utils.FileUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileNotFoundException;
import java.security.Security;

import static com.pdfsignature.utils.FileUtil.getCryptoToken;

public class PDFSignerTest {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        String input = "C:\\Users\\LinhVu\\Desktop\\signpdf\\src\\main\\java\\com\\pdfsignature\\files\\test.pdf";
        String output = "C:\\Users\\LinhVu\\Desktop\\signpdf\\src\\main\\java\\com\\pdfsignature\\files\\test_signed.pdf";
        String keystorePath = "C:\\Users\\LinhVu\\Desktop\\signpdf\\src\\main\\java\\com\\pdfsignature\\files\\badssl.p12";
        String keystorePass = "badssl.com";
        try {
            long startTime = System.currentTimeMillis();
            CryptoToken token = getCryptoToken(keystorePath, keystorePass);
            sign(input, output, token);
            System.out.println("\nsign in: " + (System.currentTimeMillis() - startTime));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void sign(String input, String output, CryptoToken token) {
        byte[] data;
        try {
            data = FileUtil.readBytesFromFile(input);
            byte[] signed = PDFSigner.sign(data, token);
            FileUtil.writeToFile(signed, output);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
