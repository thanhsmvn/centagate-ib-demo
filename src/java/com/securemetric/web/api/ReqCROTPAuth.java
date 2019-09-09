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
/**
 *
 * @author auyong
 */
public class ReqCROTPAuth {

    private String strHMAC = null;
    public HashMap<String , String> Authenticate(String username, String password, String ipAddress, String userAgent) 
    {
        /*requestOtpChallenge*/
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
        String displayMessage = "<Root><VN><Field1><Caption>Mã giao dịch 123 :</Caption><Data>876453235</Data><Color>e49717</Color></Field1><Field2><Caption>Từ tài khoản</Caption><Data>8764532345667775</Data><Color>F9333333</Color></Field2><Field3><Caption>Đến tài khoản</Caption><Data>8764532333432545</Data><Color>F9333333</Color></Field3><Field4><Caption>Số tiền</Caption><Data>6660.000.000</Data><Color>e49717</Color></Field4></VN><EN><Field1><Caption>Transaction ID</Caption><Data>876453235</Data><Color>e49717</Color></Field1><Field2><Caption>From Account</Caption><Data>8764532345667775</Data><Color>F9333333</Color></Field2><Field3><Caption>To Account</Caption><Data>8764532333432545</Data><Color>F9333333</Color></Field3><Field4><Caption>Amount</Caption><Data>60.000.000</Data><Color>e49717</Color></Field4></EN></Root>";
        String pushNotificationMessage = "Bạn có yêu cầu xác thực";
        /* Put all the required parameters for basic authentication */ 
        HashMap<String,String> map = new HashMap( ) ; 
        map.put ( "username" , username ) ; 	
        map.put ( "integrationKey" , integrationKey ) ; 
        map.put ( "unixTimestamp" , unixTimestamp ) ; 
        map.put ( "ipAddress" , ipAddress ) ; /* The client’s IP address */ 
        map.put ( "userAgent" , userAgent ) ; /* The client’s user agent */ 
        map.put ( "hmac" , secureRestClientTrustManager.calculateHmac256 (
                   secretKey , 
                   username + integrationKey + unixTimestamp + ipAddress + userAgent));

        /* Read the output returned from the authentication */ 
        Gson gson = new Gson (); /*GSON library*/
        
        com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );
        WebResource service = client.resource ( APIController.getBaseURI()+  "/auth/requestOtpChallenge"  );
        ClientResponse response = service.accept ( MediaType.APPLICATION_JSON ).post ( ClientResponse.class , gson.toJson ( map ) );
         System.out.println("DEBUG Message[ReqCROTPAuth] : Call API " + response.toString()); 
        if(response.getStatus() == 200)
        {    
            authString = response.getEntity ( String.class ) ;  
            responseMap = gson.fromJson ( authString , HashMap.class );
            System.out.println("DEBUG Message[ReqCROTPAuth] : " + authString);
        }
           
        }catch (Exception e){
            System.out.println("Error");
            System.out.println("DEBUG Message[ReqCROTPAuth] : Failed with exception " + e.getMessage()); 
            e.printStackTrace();
        } 

        return responseMap; 
    }

//public HashMap<String , String> Authenticate(String username, String password, String ipAddress, String userAgent) 
//    {
//        /*requestOtpChallenge*/
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
//        String displayMessage = "<Root><VN><Field1><Caption>Mã giao dịch</Caption><Data>NIB-TAU4243021112185e409600af4fc291</Data></Field1><Field2><Caption>Thời gian giao dịch</Caption><Data>11/12/2018 08:43:41</Data></Field2><Field3><Caption></Caption><Data></Data></Field3><Field4><Caption></Caption><Data></Data></Field4><Field5><Caption></Caption><Data></Data></Field5><Field6><Caption></Caption><Data></Data></Field6></VN><EN><Field1><Caption>Transaction ID</Caption><Data>NIB-TAU4243021112185e409600af4fc291</Data><Color></Color></Field1><Field2><Caption>Transaction Time</Caption><Data>11/12/2018 08:43:41</Data><Color></Color></Field2><Field3><Caption></Caption><Data></Data><Color></Color></Field3><Field4><Caption></Caption><Data></Data><Color></Color></Field4><Field5><Caption></Caption><Data></Data><Color></Color></Field5><Field6><Caption></Caption><Data></Data><Color></Color></Field6></EN></Root>";
//        String pushNotificationMessage = "Vui lòng xác thực giao dịch/ Please verify the transaction";
//        /* Put all the required parameters for basic authentication */ 
//        HashMap<String,String> map = new HashMap( ) ; 
//        map.put ( "username" , username ) ; 	
//        map.put ( "details", "TklCLVRBVTI4MjgwODA3MTIxODJlMWQ1N2FmM2M1OTlmNmI=");
//        map.put ( "push_notification_message" , pushNotificationMessage ) ; 
//        map.put ( "display_message" ,  displayMessage) ; 
//        map.put ( "integrationKey" , integrationKey ) ; 
//        map.put ( "unixTimestamp" , unixTimestamp ) ; 
//        map.put ( "ipAddress" , ipAddress ) ; /* The client’s IP address */ 
//        map.put ( "userAgent" , userAgent ) ; /* The client’s user agent */ 
//        map.put ( "hmac" , secureRestClientTrustManager.calculateHmac256 (
//                   secretKey , 
//                   username + integrationKey + unixTimestamp + ipAddress + userAgent));
//
//        /* Read the output returned from the authentication */ 
//        Gson gson = new Gson (); /*GSON library*/
//        
//        com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );
//        WebResource service = client.resource ( APIController.getBaseURI()+  "/auth/requestMobilePushSignOTP"  );
//        ClientResponse response = service.accept ( MediaType.APPLICATION_JSON ).post ( ClientResponse.class , gson.toJson ( map ) );
//         System.out.println("DEBUG Message[ReqCROTPAuth] : Call API " + response.toString()); 
//        if(response.getStatus() == 200)
//        {    
//            authString = response.getEntity ( String.class ) ;  
//            responseMap = gson.fromJson ( authString , HashMap.class );
//            System.out.println("DEBUG Message[ReqCROTPAuth] : " + authString);
//        }
//           
//        }catch (Exception e){
//            System.out.println("Error");
//            System.out.println("DEBUG Message[ReqCROTPAuth] : Failed with exception " + e.getMessage()); 
//            e.printStackTrace();
//        } 
//
//        return responseMap; 
//    }
//    public HashMap<String, String> Authenticate(String username, String password, String ipAddress, String userAgent) {
//        /*requestOtpChallenge*/
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
//            APIController.calculateHmac256(secretKey, "");
//            String displayMessage = "<Root><VN><Field1><Caption>Mã giao dịch</Caption><Data>NIB-TAU4243021112185e409600af4fc291</Data></Field1><Field2><Caption>Thời gian giao dịch</Caption><Data>11/12/2018 08:43:41</Data></Field2><Field3><Caption></Caption><Data></Data></Field3><Field4><Caption></Caption><Data></Data></Field4><Field5><Caption></Caption><Data></Data></Field5><Field6><Caption></Caption><Data></Data></Field6></VN><EN><Field1><Caption>Transaction ID</Caption><Data>NIB-TAU4243021112185e409600af4fc291</Data><Color></Color></Field1><Field2><Caption>Transaction Time</Caption><Data>11/12/2018 08:43:41</Data><Color></Color></Field2><Field3><Caption></Caption><Data></Data><Color></Color></Field3><Field4><Caption></Caption><Data></Data><Color></Color></Field4><Field5><Caption></Caption><Data></Data><Color></Color></Field5><Field6><Caption></Caption><Data></Data><Color></Color></Field6></EN></Root>";
//            String pushNotificationMessage = "Vui lòng xác thực giao dịch/ Please verify the transaction";
//            /* Put all the required parameters for basic authentication */
//            HashMap<String, String> map = new HashMap();
//            map.put("username", username);
//            map.put("details", "TklCLVRBVTI4MjgwODA3MTIxODJlMWQ1N2FmM2M1OTlmNmI=");
//            map.put("push_notification_message", pushNotificationMessage);
//            map.put("display_message", displayMessage);
//            map.put("integrationKey", integrationKey);
//            map.put("unixTimestamp", unixTimestamp);
//            map.put("ipAddress", ipAddress);
//            /* The client’s IP address */
//            map.put("userAgent", userAgent);
//            /* The client’s user agent */
//            map.put("hmac", secureRestClientTrustManager.calculateHmac256(
//                    secretKey,
//                    username + integrationKey + unixTimestamp + ipAddress + userAgent));
//
//            /* Read the output returned from the authentication */
//            Gson gson = new Gson();
//            /*GSON library*/
//
//            com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );
//            WebResource service = client.resource(APIController.getBaseURI() + "/auth/requestMobilePushSignOTP");
//            ClientResponse response = service.accept(MediaType.APPLICATION_JSON).post(ClientResponse.class, gson.toJson(map));
//            System.out.println("DEBUG Message[ReqCROTPAuth] : Call API " + response.toString());
//            if (response.getStatus() == 200) {
//                authString = response.getEntity(String.class);
//                responseMap = gson.fromJson(authString, HashMap.class);
//                System.out.println("DEBUG Message[ReqCROTPAuth] : " + authString);
//            }
//
//        } catch (Exception e) {
//            System.out.println("Error");
//            System.out.println("DEBUG Message[ReqCROTPAuth] : Failed with exception " + e.getMessage());
//            e.printStackTrace();
//        }
//
//        return responseMap;
//    }

//    public HashMap<String, String> Authenticate(String username, String password, String ipAddress, String userAgent) {
//        /*requestOtpChallenge*/
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
//            HashMap<String, String> map = new HashMap();
//            map.put("username", username);
//            String details = "YWJjMTIz";
//            map.put("details", details);
//            String transId = "abc123";
//            map.put("transactionId", transId);
//            map.put("integrationKey", integrationKey);
//            map.put("unixTimestamp", unixTimestamp);
//            map.put("ipAddress", ipAddress);
//            /* The client’s IP address */
//            map.put("userAgent", userAgent);
//            /* The client’s user agent */
//            map.put("hmac", secureRestClientTrustManager.calculateHmac256(
//                    secretKey,
//                    username + details + transId + integrationKey + unixTimestamp + ipAddress + userAgent));
//
//            /* Read the output returned from the authentication */
//            Gson gson = new Gson();
//            /*GSON library*/
//
//            com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );
//            WebResource service = client.resource(APIController.getBaseURI() + "/trans/requestTransactionSigningChallenge");
//            ClientResponse response = service.accept(MediaType.APPLICATION_JSON).post(ClientResponse.class, gson.toJson(map));
//            System.out.println("DEBUG Message[ReqCROTPAuth] : Call API " + response.toString());
//            if (response.getStatus() == 200) {
//                authString = response.getEntity(String.class);
//                responseMap = gson.fromJson(authString, HashMap.class);
//                System.out.println("DEBUG Message[ReqCROTPAuth] : " + authString);
//            }
//
//        } catch (Exception e) {
//            System.out.println("Error");
//            System.out.println("DEBUG Message[ReqCROTPAuth] : Failed with exception " + e.getMessage());
//            e.printStackTrace();
//        }
//
//        return responseMap;
//    }
}
