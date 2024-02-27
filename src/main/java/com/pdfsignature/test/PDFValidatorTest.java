package com.pdfsignature.test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Security;
import java.security.cert.X509Certificate;

import com.pdfsignature.pdf.PDFValidator;
import com.pdfsignature.utils.CryptoToken;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.pdfsignature.utils.FileUtil;

public class PDFValidatorTest {

	public static void main(String[] args) {
		String signedDoc = "C:\\Users\\LinhVu\\Desktop\\signpdf\\src\\main\\java\\com\\pdfsignature\\files\\test_signed.pdf";
		String keystorePath = "C:\\Users\\LinhVu\\Desktop\\signpdf\\src\\main\\java\\com\\pdfsignature\\files\\badssl.p12";
		String keystorePass = "badssl.com";

		CryptoToken token;
		try {
			token = FileUtil.getCryptoToken(keystorePath, keystorePass);
		} catch (FileNotFoundException e) {
			token = null;
		}
		verify(signedDoc, token);
	}

	public static void verify(String signedDoc, CryptoToken token) {
		Security.addProvider(new BouncyCastleProvider());
		byte[] signedData;
		try {
			signedData = FileUtil.readBytesFromFile(signedDoc);
			System.out.println("---> Result code: " + PDFValidator
					.verify(signedData, token));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
