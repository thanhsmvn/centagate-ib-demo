/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.securemetric.web.api;

import com.securemetric.web.util.Config;
import com.sun.jersey.core.util.Base64;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Properties;
import java.util.ResourceBundle;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.UriBuilder;
import org.apache.commons.codec.binary.Hex;

/**
 *
 * @author auyong
 */
public class APIController {

    private String strHMAC = null;

    public HashMap<String, String> RequestOTP(String username, String password, String reqMethod, String authToken, String ipAddress, String userAgent, String details) {
        if (reqMethod == null) {
            return null;
        }

        HashMap<String, String> authString = new HashMap();

        if (reqMethod.equals("2")) {
            ReqSMSAuth smsAuth = new ReqSMSAuth();
            authString = smsAuth.Authenticate(username, password, ipAddress, userAgent);
        } else if (reqMethod.equals("3"))//since the demo using the OTP so we no need request chanlenge code
        {
            //no request required for time-based otp
//            ReqCROTPAuth otpAuth = new ReqCROTPAuth();
//            authString = otpAuth.Authenticate(username, password,ipAddress,userAgent);  

            ReqOTPAuth otpAuth = new ReqOTPAuth();
            authString = otpAuth.requestOTP(username, password, ipAddress, userAgent);
        } else if (reqMethod.equals("5")) {
            //request for challenge code
            ReqCROTPAuth otpAuth = new ReqCROTPAuth();
            authString = otpAuth.Authenticate(username, password, ipAddress, userAgent);

//            ReqQrAuth qrAuth = new ReqQrAuth();
//            authString = qrAuth.Authenticate(username, password,authToken,ipAddress,userAgent, details);  
        }else if (reqMethod.equals("9")) {
            ReqSigningOTPAuth signingAuth = new ReqSigningOTPAuth();
            authString = signingAuth.Authenticate(username, password, ipAddress, userAgent);
        
        }else if (reqMethod.equals("4")) {

            ReqQrAuth qrAuth = new ReqQrAuth();
            authString = qrAuth.Authenticate(username, password, authToken, ipAddress, userAgent, details);
        } else if (reqMethod.equals("7")) {

            ReqQna qna = new ReqQna();
            authString = qna.Authenticate(username, authToken, ipAddress, userAgent);
        } else if (reqMethod.equals("8")) {

            ReqMobilePushCr reqMobilePushCr = new ReqMobilePushCr();
            authString = reqMobilePushCr.Authenticate(username, password, authToken, ipAddress, userAgent, details);
        }

        return authString;
    }

    public HashMap<String, String> Authenticate(String username, String password, String authMethod, String otp, String otpChallenge, String authToken, String ipAddress, String userAgent, String browserFp, String certFingerprint, int quesSize, String[][] qnaAns) {
        if (authMethod == null) {
            return null;
        }

        HashMap<String, String> authString = new HashMap();

        if (authMethod.equals("2")) {
            SMSAuth smsAuth = new SMSAuth();
            authString = smsAuth.Authenticate(username, otp, authToken, ipAddress, userAgent, browserFp);
        } else if (authMethod.equals("3")) {
            OTPAuth otpAuth = new OTPAuth();
            authString = otpAuth.Authenticate(username, otp, authToken, ipAddress, userAgent, browserFp);
        } else if (authMethod.equals("5")) {
            CROTPAuth otpAuth = new CROTPAuth();
            authString = otpAuth.Authenticate(username, password, otp, otpChallenge, authToken, ipAddress, userAgent, browserFp);
        } else if (authMethod.equals("9")){
            SigningOTPAuth signingAuth = new SigningOTPAuth();
            authString = signingAuth.Authenticate(username, password, otp, otpChallenge, authToken, ipAddress, userAgent, browserFp);
        } else if (authMethod.equals("1")) {
            BasicAuth basicAuth = new BasicAuth();
            authString = basicAuth.Authenticate(username, password, ipAddress, userAgent, browserFp);
        } else if (authMethod.equals("6")) {
            PkiAuth pkiAuth = new PkiAuth();
            authString = pkiAuth.Authenticate(username, certFingerprint, authToken, ipAddress, userAgent, browserFp);
        } else if (authMethod.equals("7")) {
            QnaAuth qnaAuth = new QnaAuth();
            authString = qnaAuth.Authenticate(username, authToken, ipAddress, userAgent, browserFp, quesSize, qnaAns);
        }

        return authString;
    }

    public HashMap<String, String> Transaction(String username, String authMethod, String otp, String otpChallenge, String authToken, String qrPlainText, String ipAddress, String userAgent, String browserFp) {
        if (authMethod == null) {
            return null;
        }

        HashMap<String, String> authString = new HashMap();
        if (authMethod.equals("2")) {
            SMSAuth smsAuth = new SMSAuth();
            authString = smsAuth.Authenticate(username, otp, authToken, ipAddress, userAgent, browserFp);
        } else if (authMethod.equals("3")) {
            OTPAuth otpAuth = new OTPAuth();
            authString = otpAuth.Authenticate(username, otp, authToken, ipAddress, userAgent, browserFp);
        } else if (authMethod.equals("4")) {
            QROTPAuth qrOTPAuth = new QROTPAuth();
            authString = qrOTPAuth.Authenticate(username, otp, otpChallenge, authToken, qrPlainText, ipAddress, userAgent, browserFp);
        } else if (authMethod.equals("5")) {
            CROTPAuth crOtpAuth = new CROTPAuth();
            authString = crOtpAuth.Authenticate(username, ipAddress, otp, otpChallenge, authToken, ipAddress, userAgent, browserFp);
        } else if (authMethod.equals("9") ){
            SigningOTPAuth signingAuth = new SigningOTPAuth();
            authString = signingAuth.Authenticate(username, ipAddress, otp, otpChallenge, authToken, ipAddress, userAgent, browserFp);
        }

        return authString;
    }

    private void setHash(String hash) {
        strHMAC = hash;
    }

    public String getHash() {
        return (strHMAC);
    }

    public static URI getBaseURI() {
        Config config = new Config();
        Properties sysProp = config.getConfig(Config.TYPE_SYSTEM);
        //   ResourceBundle resource = ResourceBundle.getBundle("system");
        return UriBuilder.fromUri(sysProp.getProperty(Config.API_URL)).build();
    }

    public static String getIntegrationKey() {
        Config config = new Config();
        Properties sysProp = config.getConfig(Config.TYPE_SYSTEM);
        //ResourceBundle resource = ResourceBundle.getBundle("system");
        return sysProp.getProperty(Config.INTEGRATION_KEY);
    }
    
    
    public static String getCenToken() {
        Config config = new Config();
        Properties sysProp = config.getConfig(Config.TYPE_SYSTEM);
        //ResourceBundle resource = ResourceBundle.getBundle("system");
        return sysProp.getProperty(Config.CEN_TOKEN);
    }

    public static String getSecretKey() {
        Config config = new Config();
        Properties sysProp = config.getConfig(Config.TYPE_SYSTEM);
        // ResourceBundle resource = ResourceBundle.getBundle("system");
        return sysProp.getProperty(Config.SECRET_KEY);//resource.getString("secretkey");
    }

    public static String calculateHmac256(String secret, String message) {
        String hash = null;
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
            sha256_HMAC.init(secret_key);

            hash = Hex.encodeHexString(sha256_HMAC.doFinal(message.getBytes()));

        } catch (Exception e) {
        } finally {
            return hash;
        }
    }

    public static String genLoginID(String secret, String message) {
        String hash = null;
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA1");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA1");
            sha256_HMAC.init(secret_key);

            hash = Hex.encodeHexString(sha256_HMAC.doFinal(message.getBytes()));

        } catch (Exception e) {
        } finally {
            return hash;
        }
    }

    public static String generateCenToken(String key, String plainText) throws NoSuchAlgorithmException,
            InvalidKeyException,
            IllegalStateException,
            UnsupportedEncodingException,
            SignatureException,
            NoSuchProviderException,
            Exception {
        final SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        final Mac mac = Mac.getInstance("HmacSHA256");

        mac.init(secretKey);

        final byte[] bytes = mac.doFinal(plainText.getBytes("UTF-8"));

        return Hex.encodeHexString(bytes);
    }

    public static void TrustAllService() throws KeyManagementException, Exception {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
                // Trust always
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
                // Trust always
            }
        }};
        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        // Create empty HostnameVerifier
        HostnameVerifier hv = new HostnameVerifier() {
            public boolean verify(String arg0, SSLSession arg1) {
                return true;
            }
        };

        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier(hv);
    }

    public static void main(String args[]) throws UnsupportedEncodingException, Exception {

        String user = "ndthanhuser";
        String otp = "foo123";
        String unixTimestamp = String.valueOf(System.currentTimeMillis() / 1000L);
        //office thanh
        String secretKey = "p98rjXh03qHX";
        String integrationKey = "ee9228e350b10b744aff1135e01f3d1c858bcd25e84dd7038946bdb73144653d";
        System.out.println(generateCenToken("ajwP19HvxYKCKi0qqC9DbYVLj3GxAkSH", "webadmin2jDmXsTYBcoTCsbVoFYuYptF3QPCAsQUZ9eOSe/ySHFQ="));
        System.out.println(300*1L);
        
        
        String base64Certificate = "MIIFCzCCAvOgAwIBAgIIRXujDXSJpVgwDQYJKoZIhvcNAQELBQAwRjEVMBMGA1UE" +
            "AwwMTWFuYWdlbWVudENBMSAwHgYDVQQKDBdTZWN1cmVNZXRyaWMgVGVjaG5vbG9n" +
            "eTELMAkGA1UEBhMCTVkwHhcNMTkwMTE2MDc0MjU0WhcNMjAwNTIyMDQwMDAwWjCB" +
            "nzEUMBIGA1UEAwwLdGVzdEFnZW5jeTQxDDAKBgNVBAsMA091MTEMMAoGA1UECwwD" +
            "T3UyMTkwNwYDVQQKDDBDaOG7qW5nIHRoxrAgc+G7kSBuw6B5IMSRw6MgxJHGsOG7" +
            "o2MgY8OgaSDEkeG6t3QxMDAuBgNVBAcMJ0tow7RuZyB0aOG7gyBn4buNaSB0aMOg" +
            "bmggcGjhuqduIGNyeXB0bzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB" +
            "AMS6lLikIdsIV9sIwcYGz6IyGU/p4buk3kyRujzajXOnq1Kq66Qe/sQZ6qdQyq5g" +
            "td5BRzG2SK0FqerbkS2Xz7XuH889FRyfzy4bFJbrzJWJbQ6hUPEoJPY16nOe8noQ" +
            "SvYAKOuekb75bUclmezcF7Je2YPqcczhI5kmoS3X0xgvx1YXTlQLSxpt07c4tlCo" +
            "C9dm+eCZewkTBeJ03gHw9gGHx5oprfK/nICPe2vhsKtgJVYIb1mkpgSlGWfRNmGn" +
            "6Wbm2D4/UC34BsYif5RS9GyiLt4hyy0fSKSNyujDXpAnEf9u/4oeSb79SmBinac7" +
            "g5/fKOEloMC7fJU0MwkzFn0CAwEAAaOBojCBnzAMBgNVHRMBAf8EAjAAMB8GA1Ud" +
            "IwQYMBaAFBd/sGUJlri6pQds5HgMAhDB47MyMCAGA1UdEQQZMBeBFXRlc3RBZ2Vu" +
            "Y3k0QGdtYWlsLmNvbTAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwHQYD" +
            "VR0OBBYEFJSiKlNit1q6K+07eclO+ckBRN9GMA4GA1UdDwEB/wQEAwIF4DANBgkq" +
            "hkiG9w0BAQsFAAOCAgEAXJxlAzWngCVFMLZtuZjH3owNLBOxaTODZPmliLFxaY/2" +
            "BktDSWIfqzqRycG03pGTxNva0Z6jZP+V2/ctDbUQ6/BTDa5cuTg0wNJaFEIftoue" +
            "BQyVYB+xqtcN9HxdHZJJ+rM2MitE0qTLMdzEGBZOi4JR80NlZ4qtUFltnU3DulP5" +
            "DLyVhPglSgbMtIGpDVc2E4dohxbat8cNY6O5AbWj7zCdFhWV84IaqT5HYMo1D1rg" +
            "uFzLK3D8882mC31S2PFsSwdkczQ5DMMkv3sgI3B8T2lEGvt0KCe2GlV0A495FI+0" +
            "NS7VXfKoTFBkC0KjV5jJpF9piZfqoxJ+It4EIfm092P3tvgEK1pbsiTWYQ1iJfkF" +
            "PnxK3niP3bdQ3rv2gM8BP3JcMr6v6Srq1Gdd0EemOrqOiwpFR1ZbwuwKv5QZbCH7" +
            "4m44/gj55AXCTNVqP+w0vmx24e57kNXeuYP894K0zf2lA2jxwT5v7tvCJpMeEW7V" +
            "Mf3yGfa1ojmY/vHtERUk6txdQS/PGTIOkV/BMMRHruJmL+g6+L7Jsx+8p5d5bXB8" +
            "odwKc5aFSU+WwIVnAGmKU3pDj2xTm5sTsHMjLqiYhMI3uc0iAebBwmniAo0cJkhR" +
            "ruiEf8w7gVIMrHkqqtrXdWQA4xsFy9ijS4QpJ4WsTFJO8fZRwCQuWUvgxSGV2YU=";
        byte[] decodedCertificate = Base64.decode(base64Certificate);
        InputStream inputStream = new ByteArrayInputStream(decodedCertificate);
        
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(inputStream);
        String publicKey = new String(new BigInteger(certificate.getPublicKey().getEncoded()).toString());
        System.out.println(publicKey);
        System.out.println(certificate.getSubjectDN().getName());
        
    }

}
