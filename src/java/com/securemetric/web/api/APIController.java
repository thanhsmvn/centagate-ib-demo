/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.securemetric.web.api;

import com.google.gson.Gson;
import com.securemetric.web.servlet.RestfulUtil;
import com.securemetric.web.util.Config;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Properties;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.MediaType;
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
        } else if (reqMethod.equals("9")) {
            ReqSigningOTPAuth signingAuth = new ReqSigningOTPAuth();
            authString = signingAuth.Authenticate(username, password, ipAddress, userAgent);

        } else if (reqMethod.equals("4")) {

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
        } else if (authMethod.equals("9")) {
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
        } else if (authMethod.equals("9")) {
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

//        String user = "webadmin";
//        String otp = "foo123";
//        String unixTimestamp = String.valueOf(System.currentTimeMillis() / 1000L);
//        System.out.println(unixTimestamp);
//        //office thanh
//        String secretKey = "p98rjXh03qHX";
//        String integrationKey = "ee9228e350b10b744aff1135e01f3d1c858bcd25e84dd7038946bdb73144653d";
//        System.out.println(calculateHmac256(secretKey, user + otp + integrationKey + unixTimestamp));
//        System.out.println(generateCenToken("p8l41FbjuxQ9z4m2dkztpDsnbMoi2C9k", user + "CCJzCGxw8/9E2IzesoGMqyzz1kqle0NQ1k4xa0nDp7E="));

//        PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Base64.decode("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB2ZP5AMQZbKdc3Q7nfSqull0gpVGgjfBxP6Ul+ln1rIhhBt/wD9MIlJw6uyu7oTVSvLtxnqH2txQvxNK2SYAupWsB/iYQ6UxZ8FQ0AesbX7Ld8xrKiQZDt8yDw7wIe2h3AdoQ0PSY9MEkUXN/tgF8DG9gaK22RJBql5XBX9Ho6T4rX8Y=")));
//
//        Signature signature = Signature.getInstance("SHA1withECDSA");
//        signature.initVerify(publicKey);
//        signature.update("https://192.168.1.202/CentagateWS/webresources|d8d7f4806a35bfac6ea3df56c276c5ff".getBytes());
//        final boolean verify = signature.verify(Base64.decode("MIGIAkIAux36oAW4G2AWs3Tc9YepPb0IIMiEVlqBxYiDw+73C5chOMu2k7GC4q+VDHLV5iggKFpd+W5xGLHsSd+tMhPwCYoCQgFybJGV9FsN9JizF+SQoZ7zj/ubWm/B8MMp8YPtivK/zrNvAVTCwfw8oEqbAshmwC9p30Qup9TuaZ/eoe4jRSGIjw=="));
//        System.out.println(verify);

        com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();
        HashMap<String, String> map = new HashMap();
        map.put("username", "thanhthanhthanh");
        map.put("firstName", "Thanh");
        map.put("lastName", "Nguyen Dang");
        map.put("userApp", "testSMS2");
        map.put("userUniqueId", " ");
        map.put("userClientId", "thanhthanhthanh");
        map.put("cenToken", "2681f8b16d8182222dbb79d76e14ab77e5afde71baac2eccbe9826508ee81090");

        //map.put("cenToken", APIController.getCenToken());
        WebResource service = client.resource(UriBuilder.fromUri("https://118.70.13.108:3443/CentagateWS/webresources").build()).path("user").path("registerUserActive").path("webadmin");

        for (int i=0;i<5;i++) {
            new Thread(new AddUserThread(service, map)).start();
        }

    }


}

class AddUserThread implements Runnable {
    private final WebResource service;
    private final HashMap<String, String> map;

    public AddUserThread(WebResource service, HashMap<String, String> map) {
        this.service = service;
        this.map = map;
    }
    
    @Override
    public void run() {
        service.accept(MediaType.APPLICATION_JSON).put(ClientResponse.class, new Gson().toJson(map));
    }
    
}
