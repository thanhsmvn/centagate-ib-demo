/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.securemetric.web.api;

import com.google.gson.Gson;
import com.securemetric.web.servlet.RestfulUtil;
import java.util.HashMap;
import javax.ws.rs.core.MediaType;
import com.securemetric.web.util.SecureRestClientTrustManager;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author auyong
 */
public class CROTPAuth {
     private String strHMAC = null;
//    public HashMap<String , String> Authenticate(String username, String password, String otp, String challenge, String authToken, String ipAddress, String userAgent, String browserFp) 
//    {
//        /*POST API REQUEST*/
//        
//        String authString = null;
//        HashMap<String , String> responseMap = new HashMap( ) ; 
//        try {
//        SecureRestClientTrustManager secureRestClientTrustManager = new SecureRestClientTrustManager(); 
//        /* The integration key. This is the key you get from the update app page inside the CENTAGATE */ 
//        String integrationKey = APIController.getIntegrationKey();   
//        /* The current time in second (GMT+00:00) */ 
//        String unixTimestamp = String.valueOf ( System.currentTimeMillis ( ) / 1000L ) ;  
//        /* The secret key. This is the key you get from the update app page inside the CENTAGATE */ 
//        String secretKey = APIController.getSecretKey();
//        /* Put all the required parameters for basic authentication */ 
//        HashMap<String,String> map = new HashMap( ) ; 
//        map.put ( "username" , username ) ; 
//        map.put ( "crOtp" , otp ) ; 	
//        map.put ( "integrationKey" , integrationKey ) ; 
//        map.put ( "unixTimestamp" , unixTimestamp ) ; 
//        map.put ( "challenge" , challenge ) ;
//        map.put ( "ipAddress" , ipAddress ) ; /* The client’s IP address */ 
//        map.put ( "userAgent" , userAgent ) ; /* The client’s user agent */ 
//        map.put ( "browserFp" , browserFp ) ;
//        map.put ( "hmac" , secureRestClientTrustManager.calculateHmac256 (
//                   secretKey , 
//                   username + otp + challenge + integrationKey + unixTimestamp + authToken + ipAddress + userAgent + browserFp));
//  
//        if(authToken != null)
//            map.put ( "authToken" , authToken ) ;
//
//        /* Read the output returned from the authentication */ 
//        Gson gson = new Gson (); /*GSON library*/
//                
//        com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );
//        WebResource service = client.resource ( APIController.getBaseURI()+  "/auth/authCrOtp" );
//        ClientResponse response = service.accept ( MediaType.APPLICATION_JSON ).post ( ClientResponse.class , gson.toJson ( map ) );
//        System.out.println("DEBUG Message[CROTPAuth] : " + map.toString()); 
//        System.out.println("DEBUG Message[CROTPAuth] : Call API " + response.toString()); 
//        if(response.getStatus() == 200)
//        {    
//            authString = response.getEntity ( String.class ) ;  
//            responseMap = gson.fromJson ( authString , HashMap.class );
//            System.out.println("DEBUG Message[CROTPAuth] : " + authString); 
//        }
//           
//        }catch (Exception e){
//            System.out.println("DEBUG Message[CROTPAuth] : Failed with exception " + e.getMessage()); 
//            e.printStackTrace();
//        } 
//
//
//        return responseMap; 
//    }
     
     public HashMap<String , String> Authenticate(String username, String password, String otp, String challenge, String authToken, String ipAddress, String userAgent, String browserFp) 
    {
        /*POST API REQUEST*/
        
        String authString = null;
        HashMap<String , String> responseMap = new HashMap( ) ; 
        try {
        SecureRestClientTrustManager secureRestClientTrustManager = new SecureRestClientTrustManager(); 
        /* The integration key. This is the key you get from the update app page inside the CENTAGATE */ 
        String integrationKey = APIController.getIntegrationKey();   
        /* The current time in second (GMT+00:00) */ 
        String unixTimestamp = String.valueOf ( System.currentTimeMillis ( ) / 1000L ) ;  
        /* The secret key. This is the key you get from the update app page inside the CENTAGATE */ 
        String secretKey = APIController.getSecretKey();
        /* Put all the required parameters for basic authentication */ 
        HashMap<String,String> map = new HashMap( ) ; 
        map.put ( "username" , username ) ; 
        map.put ("details", "TklCLVRBVTI4MjgwODA3MTIxODJlMWQ1N2FmM2M1OTlmNmI=");
        map.put ( "otp" , otp ) ; 	
        map.put ( "integrationKey" , integrationKey ) ; 
        map.put ( "unixTimestamp" , unixTimestamp ) ; 
        map.put ( "ipAddress" , ipAddress ) ; /* The client’s IP address */ 
        map.put ( "userAgent" , userAgent ) ; /* The client’s user agent */ 
        map.put ( "browserFp" , browserFp ) ;
        map.put ( "hmac" , secureRestClientTrustManager.calculateHmac256 (
                   secretKey , 
                   username + otp + integrationKey + unixTimestamp + authToken + ipAddress + userAgent + browserFp));
  
        if(authToken != null)
            map.put ( "authToken" , authToken ) ;

        /* Read the output returned from the authentication */ 
        Gson gson = new Gson (); /*GSON library*/
                
        com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );
        WebResource service = client.resource ( APIController.getBaseURI()+  "/auth/authenticateMobilePushSignOTP" );
        ClientResponse response = service.accept ( MediaType.APPLICATION_JSON ).post ( ClientResponse.class , gson.toJson ( map ) );
        if(response.getStatus() == 200)
        {    
            authString = response.getEntity ( String.class ) ;  
            responseMap = gson.fromJson ( authString , HashMap.class );
        }
           
        }catch (Exception e){
        } 


        return responseMap; 
    }
     
     
//     public HashMap<String, String> Authenticate(String username, String password, String otp, String challenge, String authToken, String ipAddress, String userAgent, String browserFp) {
//        /*POST API REQUEST*/
//
//        String authString = null;
//        HashMap<String, String> responseMap = new HashMap();
//        try {
//            SecureRestClientTrustManager secureRestClientTrustManager = new SecureRestClientTrustManager();
//            /* The integration key. This is the key you get from the update app page inside the CENTAGATE */
//            String integrationKey = APIController.getIntegrationKey();
//            /* The current time in second (GMT+00:00) */
//            String unixTimestamp = String.valueOf(System.currentTimeMillis() / 1000L);
//            /* The secret key. This is the key you get from the update app page inside the CENTAGATE */
//            String secretKey = APIController.getSecretKey();
//            /* Put all the required parameters for basic authentication */
//            HashMap<String, String> map = new HashMap();
//            map.put("username", username);
//            map.put("otp", otp);
//             final String transId = "abc123";
//            map.put("transactionId", transId);
//            final String details = "YWJjMTIz";
//            map.put("details", details);
//           
//            
//            map.put("integrationKey", integrationKey);
//            map.put("unixTimestamp", unixTimestamp);
//            map.put("ipAddress", ipAddress);
//            /* The client’s IP address */
//            map.put("userAgent", userAgent);
//            /* The client’s user agent */
//            map.put("browserFp", browserFp);
//            map.put("hmac", secureRestClientTrustManager.calculateHmac256(
//                    secretKey,
//                    username + otp + details + transId + integrationKey + unixTimestamp + authToken + ipAddress + userAgent + browserFp));
//
//            if (authToken != null) {
//                map.put("authToken", authToken);
//            }
//
//            /* Read the output returned from the authentication */
//            Gson gson = new Gson();
//            /*GSON library*/
//
//            com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );
//            WebResource service = client.resource(APIController.getBaseURI() + "/trans/authTransactionSigningCrOtp");
//            ClientResponse response = service.accept(MediaType.APPLICATION_JSON).post(ClientResponse.class, gson.toJson(map));
//            System.out.println("DEBUG Message[CROTPAuth] : " + map.toString());
//            System.out.println("DEBUG Message[CROTPAuth] : Call API " + response.toString());
//            if (response.getStatus() == 200) {
//                authString = response.getEntity(String.class);
//                responseMap = gson.fromJson(authString, HashMap.class);
//                System.out.println("DEBUG Message[CROTPAuth] : " + authString);
//            }
//
//        } catch (Exception e) {
//            System.out.println("DEBUG Message[CROTPAuth] : Failed with exception " + e.getMessage());
//            e.printStackTrace();
//        }
//
//        return responseMap;
//    }
}
