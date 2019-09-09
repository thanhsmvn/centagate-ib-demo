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
public class ReqSigningOTPAuth {
    private String StrHMAC = null;
    
    public HashMap<String, String> Authenticate(String username, String password, String ipAddress, String userAgent){
        String authString = null;
        HashMap<String, String> responseMap = new HashMap();
        try{
            SecureRestClientTrustManager secureRestClientTrustManager = new SecureRestClientTrustManager();
            String integrationKey = APIController.getIntegrationKey();
            String unixTimestamp = String.valueOf(System.currentTimeMillis() / 1000L);
            String secretKey = APIController.getSecretKey();
            byte[] encodedBytes = "abc123".getBytes("UTF-8");
            String details = Base64.getEncoder().encodeToString(encodedBytes);
            HashMap<String,String> map = new HashMap( ) ;                       
            map.put("username", username);
            map.put("details", details);
            String transactionId = "abc123";
            map.put("transactionId", transactionId);
            map.put("integrationKey", integrationKey);
            map.put("unixTimestamp", unixTimestamp);
            map.put("ipAddress", ipAddress);
            map.put("userAgent", userAgent);
            map.put("hmac", secureRestClientTrustManager.calculateHmac256(secretKey, username + details + transactionId + integrationKey + unixTimestamp + ipAddress + userAgent));
            Gson gson = new Gson();
            
            com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();
            WebResource service = client.resource(APIController.getBaseURI()+ "/trans/requestTransactionSigningChallenge");
            ClientResponse response = service.accept(MediaType.APPLICATION_JSON).post(ClientResponse.class, gson.toJson(map));
            System.out.println("DEBUG Message[ReqSigningOTP] : call API" + response.toString());
            if (response.getStatus() == 200){
                authString = response.getEntity(String.class);
                responseMap = gson.fromJson(authString, HashMap.class);
                System.out.println("DEBUG Message[ReqSigningOTP] : " + authString);
            }
        }catch(Exception e){
            System.out.println("Error");
            System.out.println("DEBUG Message[ReqSigningOTP] : Failed with exception" + e.getMessage());
            e.printStackTrace();
        }
        return responseMap;
    }
}
