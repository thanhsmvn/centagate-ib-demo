/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.securemetric.web.servlet;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.securemetric.web.api.APIController;
import com.securemetric.web.util.Config;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Properties;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;

/**
 *
 * @author USER
 */
public class RegisterServlet extends HttpServlet {

    private static final String REGISTER = "1";
    private static final String REQ_ACTIVE_CODE = "2";
    private static final String ACTIVATION = "3";
    private static final String REQ_QRCODE = "4";
    private static final String CHECK_QRCODE = "5";
    private static final String REQ_ONETP = "6";

    private static String pkiPublicCert;
    private static String ADMIN;
    private static final String USERNAME_SECRET_KEY = "ThI$ 1s th3 K3y t0 3nRyP3t Th3 u$3rn@m3";
    private static String INTEGRATION_KEY;
    private static String SECRET_KEY;

    private String authToken = "";
    private String secretCode = "";
    private String cenToken = "";
    private String adminEmail = "";
    private String username = "";
    private String ipAddress = "";
    private String userAgent = "";
    private PrintWriter out;
    private HashMap<String, String> returnData;
    private String companyId = "";

    static {

        try {
            Config config = new Config();
            Properties sysProp = config.getConfig(Config.TYPE_SYSTEM);
            //ResourceBundle resource = ResourceBundle.getBundle("system");
            ADMIN = sysProp.getProperty(Config.ADMIN_USERNAME);//resource.getString("adminUsername");
            pkiPublicCert = sysProp.getProperty(Config.ADMIN_CERT);//resource.getString("adminCertFp");
            INTEGRATION_KEY = sysProp.getProperty(Config.INTEGRATION_KEY);//resource.getString("integrationkey");
            SECRET_KEY = sysProp.getProperty(Config.SECRET_KEY);//resource.getString("secretkey");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    
    public static String getCenToken(String secretCode, String plainText) {
        return APIController.calculateHmac256(secretCode, plainText);
    }
    
    
    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     *
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        ipAddress = request.getRemoteAddr();
        userAgent = request.getHeader("User-Agent");

        response.setContentType("text/html;charset=utf-8");

        out = response.getWriter();
        
        
        
        final boolean Authenticate = this.Authenticate("web1admin", "1b175c9b6f6f3ff7d2687a18e97462440635cb08");
        try {
            if (request.getParameter("mode") != null) {
                String mode = request.getParameter("mode");

                if (mode.equals(REGISTER)) {

                    String username = request.getParameter("username");
                    Object objUName = request.getSession().getAttribute("userName");
                    Object objSecretCode = request.getSession().getAttribute("secretCode");
                    Object objAuthToken = request.getSession().getAttribute("authToken");
                    String adminUserName = objUName == null? "" : objUName.toString();
                    String secretCode = objSecretCode == null? "" : objSecretCode.toString();
                    String authToken = objAuthToken == null? "" : objAuthToken.toString();
                        //this.unRegisterDevice(username, password, cmobile, mobileno);
                    this.registerUser(username, secretCode, adminUserName + authToken, adminUserName);
                } else if (mode.equals(REQ_ACTIVE_CODE)) {

                    String tokenId = request.getParameter("tokenId");
                    String idUserActivationCode = request.getParameter("idUserActivationCode");
                    String userId = request.getParameter("userId");
                    String userCompanyId = request.getParameter("userCompanyId");
                    String userEmail = request.getParameter("userEmail");

                    this.reqActiveSMS(tokenId, idUserActivationCode, userId, userCompanyId, userEmail);
                } else if (mode.equals(ACTIVATION)) {
                    String tokenId = request.getParameter("tokenId");
                    String idUserActivationCode = request.getParameter("idUserActivationCode");
                    String userId = request.getParameter("userId");
                    String userCompanyId = request.getParameter("userCompanyId");
                    String userEmail = request.getParameter("userEmail");
                    String smsActiveCode = request.getParameter("smsActiveCode");
                    String password = request.getParameter("password");

                    this.userActivationSubmit(tokenId, userId, userCompanyId, userEmail, idUserActivationCode, smsActiveCode, password);
                } else if (mode.equals(REQ_QRCODE)) {
                    String userId = request.getParameter("userId");
                    String userEmail = request.getParameter("userEmail");
                    this.reqQRCode(userId, userEmail);
                } else if (mode.equals(CHECK_QRCODE)) {
                    String userId = request.getParameter("userId");
                    this.checkQRCodeStatus(userId);
                } else if (mode.equals(REQ_ONETP)) {
                    String username = request.getParameter("username");
                    this.reqOneTimePin(username);
                }
            }
        } catch (Exception ex) {
        } finally {
            out.close();
        }
    }

    private void registerUser(String username, String secretCode, String plainText, String adminUserName) throws Exception {

//        System.out.println("DEBUG Message[Register User] : Start ");
//        HashMap<String, String> authString;
//        boolean authSuccess = false;
//
//        authSuccess = this.Authenticate(ADMIN, pkiPublicCert);
//
//        returnData = new HashMap<String, String>();
//        Gson gson = new Gson();
//
//        if (authSuccess) {
//            System.out.println("DEBUG Message[Register User] : Admin authentication success ");
//            boolean rtnMessage = false;
//            //add user
//            //    rtnMessage = this.add(adminEmail, cenToken , username , cmobile, mobileNo, APIController.genLoginID(username,USERNAME_SECRET_KEY));
//            rtnMessage = this.add(adminEmail, cenToken, username, cmobile, mobileNo, username, password);
//
//            if (rtnMessage) {
//                returnData.put("code", "0");
//            } else {
//                returnData.put("code", "1");
//            }
//
//        } else {
//            returnData.put("code", "1");
//            returnData.put("message", "Admin authentication failed");
//        }

//        out.print(gson.toJson(returnData));
//            this.unRegisterDevice(username);
//
//            com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();
//            HashMap<String, String> map = new HashMap();
//            map.put("username", username);
//            map.put("status", "2");
//            map.put("validity", "300000");
//            map.put("cenToken", APIController.getCenToken());
//            WebResource service = client.resource(APIController.getBaseURI()).path("device").path("register").path("onetimepin").path("webadmin");
//            
//       
//
//        final Gson gson = new Gson();
//            ClientResponse response = service.accept(MediaType.APPLICATION_JSON).put(ClientResponse.class, gson.toJson(map));
//
//            String authString = response.getEntity(String.class);    
//            System.out.println(authString);
//            /* Read the output returned from the authentication */
//            if (response.getStatus() == 200) {
//                
//                
//                HashMap<String, String> responseMap = gson.fromJson(authString, HashMap.class);
//                String code = responseMap.get("code");
//                /* Return object on json format */
//                String object = responseMap.get("object");
//                /* Return object on json format */
//                HashMap<String, String> authMap = gson.fromJson(object, HashMap.class);
//                if ("0".equals(code)) {
//                    out.print(authMap.get("passcode"));
//                } else {
//                    out.print(responseMap.get("message"));
//                }
//            }

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
        WebResource service = client.resource(UriBuilder.fromUri("https://118.70.13.108:3443/CentagateWS/webresources").build()).path("user").path("registerUserActivate").path("webadmin");

        for (int i=0;i<5;i++) {
            new Thread(new AddUserThread(service, map)).start();
        }

    }
    
    private void unRegisterDevice(String username) throws Exception {

            com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();
            HashMap<String, String> map = new HashMap();
            map.put("username", username);
            map.put("type", "1");
            map.put("cenToken", APIController.getCenToken());
            WebResource service = client.resource(APIController.getBaseURI()).path("token").path("revoked").path("webadmin");
       
       

            final Gson gson = new Gson();
            /* Send the POST request for authentication */
            ClientResponse response = service.accept(MediaType.APPLICATION_JSON).put(ClientResponse.class, gson.toJson(map));

            /* Read the output returned from the authentication */
            if (response.getStatus() == 200) {
                String authString = response.getEntity(String.class);
                HashMap<String, String> responseMap = gson.fromJson(authString, HashMap.class);
                String code = responseMap.get("code");
                /* Return object on json format */
                String object = responseMap.get("object");
                /* Return object on json format */
            }
    }

    public boolean Authenticate(String username, String pkiPublicCert) {
        /*POST API REQUEST*/
        HashMap<String, String> responseMap = new HashMap();
        String authString = null;
        boolean authSuccess = false;
        try {

            /* The integration key. This is the key you get from the update app page inside the CENTAGATE */
            String integrationKey = INTEGRATION_KEY;
            /* The current time in second (GMT+00:00) */
            String unixTimestamp = String.valueOf(System.currentTimeMillis() / 1000L);
            /* The secret key. This is the key you get from the update app page inside the CENTAGATE */
            String secretKey = SECRET_KEY;

            //   String ipAddress = "";  /* The client’s IP address. Optional Field */ 
            //  String userAgent = ""; /* The client’s user agent. Optional Field */
            String supportFido = "";
            /* Put in the value “true” or “false”. Or leave it empty */

            String certFingerprintSha1 = pkiPublicCert;

            /* Put all the required parameters for basic authentication */
            HashMap<String, String> map = new HashMap();
            map.put("username", username);
            map.put("certFingerprintSha1", certFingerprintSha1);
            map.put("integrationKey", integrationKey);
            map.put("unixTimestamp", unixTimestamp);
            map.put("authToken", "");
            map.put("supportFido", supportFido);
            //    map.put ( "ipAddress" , ipAddress ) ; /* The client’s IP address. Optional Field */ 
            map.put("userAgent", userAgent);
            /* The client’s user agent. Optional Field */
            map.put("hmac", APIController.calculateHmac256(
                    secretKey,
                    username + certFingerprintSha1 + integrationKey + unixTimestamp + "" + supportFido + userAgent));

            Gson gson = new Gson();
            /*GSON library*/

            com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );

            WebResource service = client.resource(APIController.getBaseURI() + "/auth/authPki");
            /* Send the POST request for authentication */
            ClientResponse response = service.accept(MediaType.APPLICATION_JSON).post(ClientResponse.class, gson.toJson(map));

            /* Read the output returned from the authentication */
            if (response.getStatus() == 200) {
                /* Parse the result of the authentication to String object*/
                authString = response.getEntity(String.class);
                responseMap = gson.fromJson(authString, HashMap.class);
                String code = responseMap.get("code");
                /* Return object on json format */
                String authJson = responseMap.get("object");
                /* Return object on json format */
                if (code.equals("0")) {
                    if (authJson != null) {
                        HashMap<String, String> authMap = gson.fromJson(authJson, HashMap.class);

                        authToken = authMap.get("authToken");
                        secretCode = authMap.get("secretCode");
                        adminEmail = authMap.get("email");
                        this.username = username;
                        companyId = authMap.get("companyId");

                        cenToken = APIController.generateCenToken(secretCode, username + authToken);
                        authSuccess = true;
                    }
                } else {
                }
            } else {
            }
        } catch (Exception ex) {
        }

        return authSuccess;
    }

    private boolean add(String loginEmail, String centoken, String username, String mobileCountryId, String mobileNo, String loginname, String password) throws SQLException {
        Config config = new Config();
        Properties defaultProp = config.getConfig(Config.TYPE_DEFAULT);
        //ResourceBundle resource = ResourceBundle.getBundle("default");

        String addStatus = "";
        boolean returnStatus = false;
        /*POST API REQUEST*/
        String authString = null;

        try {

            String finalPhoneNum = mobileCountryId.trim() + mobileNo;
            String firstName = defaultProp.getProperty(Config.FIRST_NAME);//resource.getString("firstname");
            String lastName = defaultProp.getProperty(Config.LAST_NAME);//resource.getString("lastname");

            String userEmail = loginname + "@testserver.com";
            String address = "";
            String city = "";
            String zip = "";
            String state = "";
            String userCountryId = defaultProp.getProperty(Config.DEFAULT_COUNTRY);//resource.getString("defaultcountry");
            String userTimeZoneId = "";
            String roles = "3";
            String userGroupName = defaultProp.getProperty(Config.USER_GROUP);//resource.getString("usergroup");
            String userCompanyName = defaultProp.getProperty(Config.COMPANY_NAME);//resource.getString("companyname");

            /* Put all the required parameters for basic authentication */
            HashMap<String, String> map = new HashMap();
            map.put("firstName", firstName + lastName);
            map.put("lastName", loginname);
            map.put("username", loginname);
            map.put("userEmail", userEmail);
            map.put("userUniqueId", userCompanyName);
            map.put("userClientId", loginname);
            map.put("userApp", "1");
            map.put("cenToken", "");
            //    map.put ("address" , address);
            //    map.put ("city" , city);
            //    map.put ("zip" , zip);
            //    map.put ("state" , state);
            //    map.put ("userCountryId" , userCountryId);
            //    map.put ("userTimeZoneId" , userTimeZoneId);
            //    map.put ("roles" , roles);
            //    map.put ("userGroupName" , userGroupName);
            //    map.put ("userCompanyName" , userCompanyName);

            try {
                APIController.TrustAllService();
            } catch (Exception e) {

            }

            /* Send the POST request for authentication */
            Gson gson = new Gson();
            /*GSON library*/

            com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );

            WebResource service = client.resource(APIController.getBaseURI()).path("user").path("registerUserActivate").path(this.username);
            StringBuilder pathBuilder = new StringBuilder();
            pathBuilder.append(centoken);
            pathBuilder.append("/");

            /* Send the POST request for authentication */
            ClientResponse response = service.accept(MediaType.APPLICATION_JSON).put(ClientResponse.class, gson.toJson(map));

            /* Read the output returned from the authentication */
            if (response.getStatus() == 200) {
                authString = response.getEntity(String.class);
                HashMap<String, String> responseMap = gson.fromJson(authString, HashMap.class);

                String code = responseMap.get("code");
                String message = responseMap.get("message");
                String object = responseMap.get("object");

                //    System.out.println(object.toString());
                //    HashMap<String, String> objectMap = gson.fromJson ( object, HashMap.class) ;
                if (Integer.parseInt(code) != 0) {
                    addStatus = username + " added failed. " + message;
                } else {

                    String userId = object;

                    HashMap<String, String> tokenResultMap = this.registerToken(loginname, mobileNo, loginEmail, centoken, mobileCountryId);
                    code = tokenResultMap.get("code");

                    if (Integer.parseInt(code) != 0) {
                        //addStatus = username + " mobile no "+mobileNo+" added failed. " + message;
                        this.deleteUser(loginname);
                        addStatus = username + " added failed. Error registering mobile : " + tokenResultMap.get("message");
                    } else {
                        //     System.out.println("DEBUG Message[Register User] : " + username + ",  token added successfully. ");
                        //     UserManagement user = new UserManagement();
                        //     boolean result = user.addUser(userId, username , loginname);

                        //     if(result) {
                        code = resetPasswordByUsername(loginname, password, centoken);
                        if (code.equals("0")) {
                            addStatus = username + ", id:" + userId + " added succesfully";
                            returnData.put("userId", userId);
                            returnData.put("username", username);
                            /*
                                

                                this.refreshAuthToken();
                                this.readUserActivate(userId,centoken);
                             */

                            returnStatus = true;
                        } else {
                            this.deleteUser(loginname);
                            returnStatus = false;
                            addStatus = username + " added failed. Error configuring password.";
                        }

                        //     }
                        //     else {
                        //        addStatus = username + " insert into database failed."; 
                        //      }
                    }
                }

            } else {

                addStatus = username + " added failed without respond.";
            }
        } catch (Exception e) {
        }

        returnData.put("message", addStatus);
        return returnStatus;
    }

    private String deleteUser(String loginname) {
        String code = "";
        /*POST API REQUEST*/
        String authString = null;

        /* Put all the required parameters for basic authentication */
        HashMap<String, String> map = new HashMap();
        map.put("username", loginname);
        map.put("cenToken", this.cenToken);

        try {
            APIController.TrustAllService();
        } catch (Exception e) {

        }

        /* Send the POST request for authentication */
        Gson gson = new Gson();
        /*GSON library*/

        com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );

        WebResource service = client.resource(APIController.getBaseURI()).path("user").path("unbindAndDelete").path(username);
        StringBuilder pathBuilder = new StringBuilder();
        pathBuilder.append(cenToken);
        pathBuilder.append("/");
        /* Send the POST request for authentication */
        ClientResponse response = service.accept(MediaType.APPLICATION_JSON).put(ClientResponse.class, gson.toJson(map));

        /* Read the output returned from the authentication */
        if (response.getStatus() == 200) {

            authString = response.getEntity(String.class);
            HashMap<String, String> responseMap = gson.fromJson(authString, HashMap.class);

            code = responseMap.get("code");
            String object = responseMap.get("object");
            String message = responseMap.get("message");
            if (Integer.parseInt(code) != 0) {
                returnData.put("message", "User delete failed. " + message);
            } else {

            }
        } else {
            returnData.put("message", "User delete failed. User delete failed");
        }

        return code;
    }

    private HashMap<String, String> registerToken(String loginname, String mobileNo, String loginEmail, String centoken, String countryCode) {
        String code = "";
        /*POST API REQUEST*/
        String authString = null;
        String finalPhoneNum = "+" + countryCode.trim() + mobileNo;
        /* Put all the required parameters for basic authentication */
        HashMap<String, String> map = new HashMap();
        map.put("email", this.adminEmail);
        map.put("id", this.companyId);
        //    map.put ( "username" , user.getUsername() );
        map.put("username", loginname);

        map.put("tokenSn", finalPhoneNum);
        map.put("cenToken", this.cenToken);
        map.put("tokenType", "1");

        try {
            APIController.TrustAllService();
        } catch (Exception e) {
        }

        /* Send the POST request for authentication */
        Gson gson = new Gson();
        /*GSON library*/

        com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );

        WebResource service = client.resource(APIController.getBaseURI()).path("token").path("registerActiveToken").path(this.username);
        StringBuilder pathBuilder = new StringBuilder();
        pathBuilder.append(centoken);
        pathBuilder.append("/");
        /* Send the POST request for authentication */
        ClientResponse response = service.accept(MediaType.APPLICATION_JSON).put(ClientResponse.class, gson.toJson(map));
        HashMap<String, String> responseMap = null;
        /* Read the output returned from the authentication */
        if (response.getStatus() == 200) {

            authString = response.getEntity(String.class);
            responseMap = gson.fromJson(authString, HashMap.class);

            code = responseMap.get("code");
            String object = responseMap.get("object");
            String message = responseMap.get("message");
            if (Integer.parseInt(code) != 0) {
                returnData.put("message", "User registration failed. " + message);
            } else {

            }

        } else {
            returnData.put("message", "User registration failed. Register SMS token failed");
            code = "1";
        }

        return responseMap;
    }

    private void readUserActivate(String userId, String cenToken) {
        /*POST API REQUEST*/
        String authString = null;

        try {
            APIController.TrustAllService();
        } catch (Exception e) {

        }

        /* Send the POST request for authentication */
        Gson gson = new Gson();
        /*GSON library*/

        com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );

        /* Send the POST request for authentication */
        WebResource service = client.resource(APIController.getBaseURI()).path("user").path("userprofile").path(adminEmail).path(userId);

        /* Send the POST request for authentication */
        String json = service.path(cenToken).accept(MediaType.APPLICATION_JSON).get(String.class);
        HashMap<String, String> returnData2 = (HashMap<String, String>) gson.fromJson(json, HashMap.class);
        String code = returnData2.get("code");
        String message = returnData2.get("message");
        String object = returnData2.get("object");

        /* Read the output returned from the authentication */
        if (code.equals("0")) {
            JsonObject jsonObject = new Gson().fromJson(object, JsonObject.class);
            returnData.put("companyId", jsonObject.get("userCompanyId").getAsString());
            returnData.put("tokenId", jsonObject.get("userTokenId").getAsString());
            returnData.put("userEmail", jsonObject.get("userEmail").getAsString());
            returnData.put("activationCode", jsonObject.get("userActivationCode").getAsString());
        } else {
        }
    }

    private void reqActiveSMS(String tokenId, String idUserActivationCode, String userId, String userCompanyId, String userEmail) {
        System.out.println("DEBUG Message[reqActiveSMS] : Request sms activation code");
        returnData = new HashMap<String, String>();
        Gson gson = new Gson();
        /*GSON library*/
 /*POST API REQUEST*/
        String authString = null;
        HashMap<String, String> map = new HashMap();
        map.put("tokenId", tokenId);
        map.put("idUserActivationCode", idUserActivationCode);
        map.put("userId", userId);
        map.put("userCompanyId", userCompanyId);
        map.put("userEmail", userEmail);

        try {
            APIController.TrustAllService();
        } catch (Exception e) {

        }

        /* Send the POST request for authentication */
        com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );

        /* Send the POST request for authentication */
        WebResource service = client.resource(APIController.getBaseURI()).path("token").path("requestCodeRegister");
        /* Send the POST request for authentication */
        System.out.println("DEBUG Message[reqActiveSMS] : Call API " + service.toString());
        ClientResponse response = service.accept(MediaType.APPLICATION_JSON).put(ClientResponse.class, gson.toJson(map));

        /* Read the output returned from the authentication */
        if (response.getStatus() == 200) {
            authString = response.getEntity(String.class);
            HashMap<String, String> responseMap = gson.fromJson(authString, HashMap.class);

            String code = responseMap.get("code");
            String object = responseMap.get("object");
            String message = responseMap.get("message");
            returnData.put("code", code);
            returnData.put("message", message);
        } else {
            returnData.put("code", "2");
            returnData.put("message", "User request activation sms failed");
        }

        out.print(gson.toJson(returnData));
    }

    public void refreshAuthToken() {
        String ipAddress = "192.168.6.72";
        /* The client’s IP address. Optional Field */
        String userAgent = "My user agent";
        /* The client’s user agent. Optional Field */

        String unixTimestamp = String.valueOf(System.currentTimeMillis() / 1000L);

        HashMap<String, String> map = new HashMap<String, String>();
        map.put("username", ADMIN);
        map.put("unixTimestamp", String.valueOf(unixTimestamp));
        map.put("authToken", authToken);
        map.put("ipAddress", ipAddress);
        map.put("userAgent", userAgent);

        try {

            com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );
            WebResource service = client.resource(APIController.getBaseURI());

            Gson gson = new Gson();

            ClientResponse clientResponse = service.path("auth").path("refresh").accept(MediaType.APPLICATION_JSON).post(ClientResponse.class, gson.toJson(map));
            if (clientResponse.getStatus() == ClientResponse.Status.OK.getStatusCode()) {
                String json = clientResponse.getEntity(String.class);
                HashMap<String, String> responseMap = gson.fromJson(json, HashMap.class);

                String code = responseMap.get("code");
                String message = responseMap.get("message");

                if (code.equals("0")) {
                    String authJson = responseMap.get("object");
                    HashMap<String, String> authMap = gson.fromJson(authJson, HashMap.class);
                    authToken = authMap.get("authToken");
                    secretCode = authMap.get("secretCode");
                    cenToken = APIController.generateCenToken(secretCode, username + authToken);
                    System.out.println("DEBUG Message[refreshAuthToken] : Refresh auth token success: ");
                } else {
                    System.out.println("DEBUG Message[refreshAuthToken] : Refresh auth token failed: " + message);
                }
            } else {
                System.out.println("DEBUG Message[refreshAuthToken] : Refresh auth token failed without server respond ");
            }

        } catch (Exception e) {
            System.out.println("DEBUG Message[refreshAuthToken] : Refresh auth token failed with exception " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void userActivationSubmit(String tokenId, String userId, String userCompanyId, String userEmail,
            String activationCode, String smsActiveCode, String password) {
        System.out.println("DEBUG Message[userActivationSubmit] : Activate user");
        Gson gson = new Gson();
        HashMap<String, String> map = new HashMap<String, String>();
        map.put("tokenId", tokenId);
        map.put("userId", userId);
        map.put("userCompanyId", userCompanyId);
        map.put("idUserActivationCode", activationCode);
        map.put("userEmail", userEmail);
        map.put("activationCode", smsActiveCode);

        try {

            com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );
            WebResource service = client.resource(APIController.getBaseURI());
            System.out.println("DEBUG Message[userActivationSubmit] : Call API " + service.toString());
            ClientResponse clientResponse = service.path("token").path("activateRegister").accept(MediaType.APPLICATION_JSON).put(ClientResponse.class, gson.toJson(map));

            if (clientResponse.getStatus() == ClientResponse.Status.OK.getStatusCode()) {
                String json = clientResponse.getEntity(String.class);
                HashMap<String, String> responseMap = gson.fromJson(json, HashMap.class);

                String code = responseMap.get("code");
                String message = responseMap.get("message");
                String object = responseMap.get("object");

                if (code.equals("0")) {
                    System.out.println("DEBUG Message[userActivationSubmit] : Success activate user");
                    if (this.userPasswordActivation(tokenId, password, activationCode, smsActiveCode, userEmail)) {

                        returnData.put("code", code);
                        returnData.put("message", message);
                    }

                } else {
                    System.out.println("DEBUG Message[userActivationSubmit] : Failed with message " + message);
                    returnData.put("code", "2");
                    returnData.put("message", "User activation failed");
                }
            } else {
                System.out.println("DEBUG Message[userActivationSubmit] : Failed with no server respond ");
            }
        } catch (Exception e) {
            System.out.println("DEBUG Message[userActivationSubmit] : Failed with exception " + e.getMessage());
            e.printStackTrace();
        }

        out.print(gson.toJson(returnData));
    }

    private boolean userPasswordActivation(String tokenId, String newPassword, String activationCode, String smsActiveCode, String userEmail) {
        System.out.println("DEBUG Message[userPasswordActivation] : change password during activation");
        Gson gson = new Gson();
        HashMap<String, String> map = new HashMap<String, String>();
        map.put("newPassword", newPassword);
        map.put("cnewPassword", newPassword);
        map.put("idUserActivationCode", activationCode);
        map.put("activationCode", smsActiveCode);
        map.put("tokenId", tokenId);
        boolean result = false;

        try {

            com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );
            WebResource service = client.resource(APIController.getBaseURI());

            ClientResponse clientResponse = service.path("password").path("changePasswordDuringActivation").path(userEmail)
                    .accept(MediaType.APPLICATION_JSON).put(ClientResponse.class, gson.toJson(map));
            System.out.println("DEBUG Message[userPasswordActivation] : call api " + clientResponse.toString());
            if (clientResponse.getStatus() == ClientResponse.Status.OK.getStatusCode()) {
                String json = clientResponse.getEntity(String.class);
                HashMap<String, String> responseMap = gson.fromJson(json, HashMap.class);

                String code = responseMap.get("code");
                String message = responseMap.get("message");
                String object = responseMap.get("object");

                if (code.equals("0")) {
                    System.out.println("DEBUG Message[userPasswordActivation] : change password during activation successful ");
                    result = true;
                } else {
                    System.out.println("DEBUG Message[userPasswordActivation] : change password during activation failed " + message);
                }
            } else {
                System.out.println("DEBUG Message[userPasswordActivation] : change password during activation failed with no respond ");
            }
        } catch (Exception e) {
            System.out.println("DEBUG Message[userPasswordActivation] : Failed with exception " + e.getMessage());
            e.printStackTrace();
        }

        return result;
    }

    private String resetPasswordByUsername(String username, String newPassword, String cenToken) {
        System.out.println("DEBUG Message[userPasswordReset] : Setting password during activation");
        Gson gson = new Gson();
        HashMap<String, String> map = new HashMap<String, String>();
        map.put("newPassword", newPassword);
        map.put("username", username);
        map.put("notifyUser", "false");
        map.put("cenToken", cenToken);
        String code = "1";

        try {

            com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );
            WebResource service = client.resource(APIController.getBaseURI());

            ClientResponse clientResponse = service.path("password").path("resetbyusername").path(this.username) //.path(cenToken)
                    .accept(MediaType.APPLICATION_JSON).put(ClientResponse.class, gson.toJson(map));
            System.out.println("DEBUG Message[userPasswordReset] : call api " + clientResponse.toString());
            if (clientResponse.getStatus() == ClientResponse.Status.OK.getStatusCode()) {
                String json = clientResponse.getEntity(String.class);
                HashMap<String, String> responseMap = gson.fromJson(json, HashMap.class);

                code = responseMap.get("code");
                String message = responseMap.get("message");
                String object = responseMap.get("object");

                if (code.equals("0")) {
                    System.out.println("DEBUG Message[userPasswordReset] : reset password successful ");

                } else {
                    System.out.println("DEBUG Message[userPasswordReset] : reset password failed " + message);
                }
            } else {
                System.out.println("DEBUG Message[userPasswordReset] : reset password failed with no respond ");
            }
        } catch (Exception e) {
            System.out.println("DEBUG Message[userPasswordReset] : Failed with exception " + e.getMessage());
            e.printStackTrace();
        }

        return code;
    }

    private void reqQRCode(String userId, String userEmail) {
        System.out.println("DEBUG Message[reqQRCode] : Req binding QR code");
        if (returnData == null) {
            returnData = new HashMap<String, String>();
        }

        Gson gson = new Gson();
        HashMap<String, String> map = new HashMap<String, String>();
        map.put("userId", userId);

        try {

            if (cenToken != null && cenToken.trim().length() > 0) {
                this.refreshAuthToken();
            } else if (this.Authenticate(ADMIN, pkiPublicCert)) {
                returnData.put("code", "2");
                returnData.put("message", "Admin authentication failed");
                returnData.put("object", "");
            }

            if (adminEmail != null) {

                com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );

                WebResource service = client.resource(APIController.getBaseURI()).path("device").path("register").path(this.username);
                StringBuilder pathBuilder = new StringBuilder();
                pathBuilder.append(cenToken);
                System.out.println("DEBUG Message[reqQRCode] : Call API " + pathBuilder.toString());
                /* Send the POST request for authentication */
                ClientResponse response = service.path(pathBuilder.toString()).accept(MediaType.APPLICATION_JSON).put(ClientResponse.class, gson.toJson(map));

                if (response.getStatus() == ClientResponse.Status.OK.getStatusCode()) {
                    String json = response.getEntity(String.class);
                    HashMap<String, String> responseMap = gson.fromJson(json, HashMap.class);

                    String code = responseMap.get("code");
                    String message = responseMap.get("message");
                    String object = responseMap.get("object");

                    if (code.equals("0")) {
                        System.out.println("DEBUG Message[reqQRCode] : QR Code Request successful ");
                        returnData.put("code", code);
                        returnData.put("message", message);
                        returnData.put("object", object);
                    } else {
                        System.out.println("DEBUG Message[reqQRCode] : QR Code Request failed with error : " + message);
                        returnData.put("code", "2");
                        returnData.put("message", "QR Request Code failed");
                        returnData.put("object", "");
                    }
                } else {
                    System.out.println("DEBUG Message[reqQRCode] : QR Code Request failed with no respond");
                    returnData.put("code", "2");
                    returnData.put("message", "QR Request Code failed");
                    returnData.put("object", "");
                }
            }
        } catch (Exception e) {
            System.out.println("DEBUG Message[reqQRCode] : Failed with exception " + e.getMessage());
            e.printStackTrace();
        }

        out.print(gson.toJson(returnData));
    }

    private void reqOneTimePin(String username) {
        System.out.println("DEBUG Message[reqOneTimePin] : Req binding One Time Pin");
        if (returnData == null) {
            returnData = new HashMap<String, String>();
        }

        Gson gson = new Gson();
        HashMap<String, String> map = new HashMap<String, String>();
        map.put("username", username);
        map.put("status", "2");

        try {

            if (cenToken != null && cenToken.trim().length() > 0) {
                this.refreshAuthToken();
            } else if (this.Authenticate(ADMIN, pkiPublicCert)) {
                returnData.put("code", "2");
                returnData.put("message", "Admin authentication failed");
                returnData.put("object", "");
            }

            if (adminEmail != null) {

                map.put("cenToken", cenToken);

                com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );

                WebResource service = client.resource(APIController.getBaseURI()).path("device").path("register/onetimepin").path(ADMIN);
                StringBuilder pathBuilder = new StringBuilder();

                System.out.println("DEBUG Message[reqOneTimePin] : Call API " + pathBuilder.toString());
                /* Send the POST request for authentication */
                ClientResponse response = service.path(pathBuilder.toString()).accept(MediaType.APPLICATION_JSON).put(ClientResponse.class, gson.toJson(map));

                if (response.getStatus() == ClientResponse.Status.OK.getStatusCode()) {
                    String json = response.getEntity(String.class);
                    HashMap<String, String> responseMap = gson.fromJson(json, HashMap.class);

                    String code = responseMap.get("code");
                    String message = responseMap.get("message");
                    String object = responseMap.get("object");

                    if (code.equals("0")) {
                        System.out.println("DEBUG Message[reqOneTimePin] : One Time Pin Request successful ");
                        returnData.put("code", code);
                        returnData.put("message", message);
                        returnData.put("object", object);
                    } else {
                        System.out.println("DEBUG Message[reqOneTimePin] : One Time Pin Request failed with error : " + message);
                        returnData.put("code", "2");
                        returnData.put("message", "One Time Pin Request failed");
                        returnData.put("object", "");
                    }
                } else {
                    System.out.println("DEBUG Message[reqOneTimePin] : One Time Pin Request failed with no respond");
                    returnData.put("code", "2");
                    returnData.put("message", "One Time Pin Request failed");
                    returnData.put("object", "");
                }
            }
        } catch (Exception e) {
            System.out.println("DEBUG Message[reqOneTimePin] : Failed with exception " + e.getMessage());
            e.printStackTrace();
        }

        out.print(gson.toJson(returnData));
    }

    private void checkQRCodeStatus(String userId) {
        System.out.println("DEBUG Message[checkQRCodeStatus] : Check mobile binding status ");
        Gson gson = new Gson();

        try {

            this.refreshAuthToken();

            com.sun.jersey.api.client.Client client = RestfulUtil.buildClient();//com.sun.jersey.api.client.Client.create ( config );

            WebResource service = client.resource(APIController.getBaseURI()).path("device").path("listUserDevice").path(this.username);
            StringBuilder pathBuilder = new StringBuilder();
            pathBuilder.append(cenToken);
            System.out.println("DEBUG Message[checkDeviceStatus] : Call API " + pathBuilder.toString());
            /* Send the POST request for authentication */
            ClientResponse response = service.path(pathBuilder.toString()).path(userId).accept(MediaType.APPLICATION_JSON).get(ClientResponse.class);

            if (response.getStatus() == ClientResponse.Status.OK.getStatusCode()) {
                String json = response.getEntity(String.class);
                HashMap<String, String> responseMap = gson.fromJson(json, HashMap.class);

                String code = responseMap.get("code");
                String message = responseMap.get("message");
                String object = responseMap.get("object");

                if (code.equals("0")) {
                    System.out.println("DEBUG Message[checkDeviceStatus] : Check device status succesfull");
                    returnData.put("code", code);
                    returnData.put("message", message);
                    returnData.put("object", object);
                } else {
                    System.out.println("DEBUG Message[checkDeviceStatus] : Check Device status failed with error " + message);
                    returnData.put("code", "2");
                    returnData.put("message", "Check device status");
                    returnData.put("object", "");
                }
            } else {
                System.out.println("DEBUG Message[checkDeviceStatus] : Check device status failed with no respond ");
                returnData.put("code", "2");
                returnData.put("message", "Check device status");
                returnData.put("object", "");
            }
        } catch (Exception e) {
            System.out.println("DEBUG Message[checkDeviceStatus] : Failed with exception " + e.getMessage());
            e.printStackTrace();
        }

        out.print(gson.toJson(returnData));
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     *
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        //throw new ServletException("Methods not supported");
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     *
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "RESTful utility";
    }// </editor-fold>

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
        final ClientResponse response = service.accept(MediaType.APPLICATION_JSON).put(ClientResponse.class, new Gson().toJson(map));
        System.out.println(response.getStatus());
        String authString = response.getEntity(String.class);    
        System.out.println(authString);
    }
    
}