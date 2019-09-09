/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.securemetric.web.api;

import com.google.gson.Gson;
import com.securemetric.web.servlet.RestfulUtil;
import com.securemetric.web.util.SecureRestClientTrustManager;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import java.util.HashMap;
import javax.ws.rs.core.MediaType;
import java.util.Base64;

/**
 *
 * @author Đức Nguyễn
 */
public class SigningOTPAuth {
    private String strHMAC = null;
    
    public HashMap<String, String> Authenticate(String username, String password, String otp, String challenge, String authToken, String ipAddress, String userAgent, String browserFp){
        String authString = null;
        HashMap<String, String> responseMap = new HashMap();
        try{
            SecureRestClientTrustManager secureRestClientTrustManager = new SecureRestClientTrustManager();
            String integrationKey = APIController.getIntegrationKey();
            String unixTimestamp = String.valueOf(System.currentTimeMillis()/1000L);
            String secretKey = APIController.getSecretKey();
            byte[] encodedBytes = "abc123".getBytes("UTF-8");
            String details = Base64.getEncoder().encodeToString(encodedBytes);
            HashMap<String, String> map = new HashMap();
            map.put("username", username);
            map.put("otp", otp);
            String transactionId = "abc123";
            map.put("transactionId", transactionId);
            map.put("details", details);
            map.put("integrationKey", integrationKey);
            map.put("unixTimestamp", unixTimestamp);
            map.put("ipAddress", ipAddress);
            /* The client’s IP address */
            map.put("userAgent", userAgent);
            /* The client’s user agent */
            map.put("browserFp", browserFp);
            map.put("hmac", secureRestClientTrustManager.calculateHmac256(secretKey, username + otp + details + transactionId + integrationKey + authToken + unixTimestamp + ipAddress + userAgent + browserFp));
            
            if(authToken != null){
                map.put("authToken", authToken);
            }
            
            
            Gson gson = new Gson();
            
            com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();
            WebResource service = client.resource(APIController.getBaseURI() + "/trans/authTransactionSigningCrOtp");
            ClientResponse response = service.accept(MediaType.APPLICATION_JSON).post(ClientResponse.class, gson.toJson(map));
            System.out.println("DEBUG Message[SigningOTPAuth] : " + map.toString());
            System.out.println("DEBUG Message[SigningOTPAuth] : Call API" + response.toString());
            if (response.getStatus() == 200){
                authString = response.getEntity(String.class);
                responseMap = gson.fromJson(authString, HashMap.class);
                System.out.println("DEBUG Message[SigningOTPAuth] : " + authString);
            }
            
        } catch(Exception e){
            System.out.println("DEBUG Message[CROTPAuth] : Failed with exception " + e.getMessage());
            e.printStackTrace();
        }
        return responseMap;
    }
}
