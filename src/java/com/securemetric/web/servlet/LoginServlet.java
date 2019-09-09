/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.securemetric.web.servlet;

import com.google.gson.Gson;
import com.google.gson.internal.LinkedTreeMap;
import com.securemetric.web.api.APIController;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.StringTokenizer;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 *
 * @author auyong
 */
public class LoginServlet extends HttpServlet {

    private final SimpleDateFormat format = new SimpleDateFormat("MM/dd/yyyy, hh:mm:ss a");

    /*
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     */
    /* @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        try {
            
            request.setCharacterEncoding("UTF-8");
            String mode = request.getParameter("MODE");
            String authReq = request.getParameter("REQ");
            String userid = request.getParameter("userid");
            String password = request.getParameter("password");           

            String consoleLog = (String) request.getSession().getAttribute("consolelog");
            request.getSession().setAttribute("consolelog", consoleLog);

            if (mode != null && (mode.equals("CLEAR") || mode.equals("LOGOUT"))) {

                request.getSession().invalidate();
            //    redirectPage(request, response, "/login.jsp");
                response.sendRedirect("/j2ee/login.jsp");
                return;
            } else if (userid == null || userid.trim().length() == 0) {

                request.getSession().setAttribute("returnMsg", "User ID cannot be empty");
                consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                        : request.getSession().getAttribute("consolelog").toString();
                consoleLog += "<br>" + format.format(new Date()) + " : ";
                consoleLog += " User ID cannot be empty";
                request.getSession().setAttribute("consolelog", consoleLog);
                redirectPage(request, response, "/login.jsp");
                return;
            } else if (password != null && password.trim().length() == 0) {
                request.getSession().setAttribute("returnMsg", "Password cannot be empty");
                consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                        : request.getSession().getAttribute("consolelog").toString();
                consoleLog += "<br>" + format.format(new Date()) + " : ";
                consoleLog += " Password cannot be empty";
                request.getSession().setAttribute("consolelog", consoleLog);
                redirectPage(request, response, "/login.jsp");
                return;
            }

            if (authReq != null) // SMSOTP or CROTP Request
            {
                this.reqAuth(request, response);
            } else //Login Request
            if (mode.equals("1")) //Basic Login
            {
                this.basicLogin(request, response);
            } else {
                this.authLogin(request, response);
            }

        } catch (Exception e) {
        }
    }

    private void basicLogin(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String mode = request.getParameter("MODE");
        String userid = request.getParameter("userid");
        String password = request.getParameter("password");
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        String browserFp = request.getParameter("browserfp");

        String consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                : request.getSession().getAttribute("consolelog").toString();
        consoleLog += "<br>" + format.format(new Date()) + " : ";
        consoleLog += " Starting to validate userName and Password...";
        request.getSession().setAttribute("consolelog", consoleLog);
        System.setProperty("jsse.enableSNIExtension", "false");
        APIController apiController = new APIController();

        HashMap<String, String> responseMap = new HashMap();

        String loginid = getUserLoginName(userid);

        responseMap = apiController.Authenticate(loginid, password, mode, "", "", "", ipAddress, userAgent, browserFp, "", 0, null);

        int code = 1;
        if (responseMap.isEmpty()) {
            request.getSession().setAttribute("returnMsg", "Authentication request failed with User ID " + userid);
            redirectPage(request, response, "/login.jsp");
            return;
        }

        code = Integer.parseInt(responseMap.get("code"));
        /* Read the output returned from the authentication */
        if (code == 0) {
            String authJson = responseMap.get("object");
            Gson gson = new Gson();
            HashMap<String, String> authMap = gson.fromJson(authJson, HashMap.class);
            String authMethods = authMap.get("authMethods");
            
            if (authMethods == null || authMethods.isEmpty()) {
                request.getSession().setAttribute("returnMsg", "Error logging in. 2FA authentication not found!");
                redirectPage(request, response, "/login.jsp");
                return;
            } else {
            
                consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                        : request.getSession().getAttribute("consolelog").toString();
                consoleLog += "<br>" + format.format(new Date()) + " : ";
                consoleLog += " Username and password validation success";
                request.getSession().setAttribute("consolelog",consoleLog);

                request.getSession().setAttribute("authToken", authMap.get("authToken"));

                /* STORED SESSION */
                request.getSession().setAttribute("authCode", "0");                
                request.getSession().setAttribute("successMsg", "Login Successful");
                request.getSession().setAttribute("returnCode", "0");
                request.getSession().setAttribute("userid", userid);
                request.getSession().setAttribute("password", password);
                request.getSession().setAttribute("loginid", loginid);
                request.getSession().setAttribute("email", authMap.get("email"));
                request.getSession().setAttribute("secretCode", authMap.get("secretCode"));
                request.getSession().setAttribute("centagateid", authMap.get("userId"));

                StringTokenizer st2 = new StringTokenizer(authMethods, ",");
                String method = "";

                while (st2.hasMoreElements()) {
                    method = st2.nextElement().toString();
                    request.getSession().setAttribute(method, method);
                }
                
                redirectPage(request, response, "/login.jsp");
                return;
            }
        } else {
            request.getSession().setAttribute("returnMsg", responseMap.get("message"));
            redirectPage(request, response, "/login.jsp");
            return;
        }
    }

    private void authLogin(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String mode = request.getParameter("MODE");
        String userid = request.getParameter("userid");
        String password = request.getParameter("password");
        String otp = request.getParameter("otp");
        String challenge = (String) request.getSession().getAttribute("crOtpChallenge");
        //      String challenge = request.getParameter("challenge");
        String passAuthToken = (null == request.getSession().getAttribute("authToken")) ? null : request.getSession().getAttribute("authToken").toString();
        String pageid = request.getParameter("pageid");
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        String certFingerPrint = (String) request.getSession().getAttribute("certFingerprint");
        String browserFp = request.getParameter("browserfp");
        String[][] qnaAns = new String[5][2];
        int quesSize = 0;

        int code = 1;
        String multiStepAuth = "false";
        String redirectPage = "", authMethods = "", authToken = "", secretCode = "", adaptiveScore = "";

        APIController apiController = new APIController();
        HashMap<String, String> responseMap = new HashMap();

        String consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                : request.getSession().getAttribute("consolelog").toString();
        consoleLog += "<br>" + format.format(new Date()) + " : ";
        if (mode.equals("2")) {//Authenticate SMS
            consoleLog += " Starting to validate SMS Token Code...";
        } else if (mode.equals("3")) {//Authenticate OTP
            consoleLog += " Starting to validate OTP Token Code...";
        } else if (mode.equals("5")) {//Authenticate cr OTP
            consoleLog += " Starting to validate CR OTP Token Code...";
        } else if (mode.equals("6")) {//Authenticate Pki Cert
            consoleLog += " Starting to validate Pki Certificate...";
        } else if (mode.equals("7")) {//Authenticate Pki Cert
            consoleLog += " Starting to validate Qna ...";
            quesSize = Integer.parseInt((String) request.getSession().getAttribute("quesSize"));

            for (int i = 0; i < quesSize; i++) {
                qnaAns[i][0] = (String) request.getParameter(i + "id");
                qnaAns[i][1] = (String) request.getParameter(i + "ans");
            }
        }

        request.getSession().setAttribute("consolelog", consoleLog);
        final String userName = getUserLoginName(userid);
        responseMap = apiController.Authenticate(userName, password, mode, otp, challenge, passAuthToken, ipAddress, userAgent, browserFp, certFingerPrint, quesSize, qnaAns);

        if (responseMap.isEmpty()) {
            request.getSession().setAttribute("returnMsg", "Authentication request failed with User ID " + userid);
            consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                    : request.getSession().getAttribute("consolelog").toString();
            consoleLog += "<br>" + format.format(new Date()) + " : ";
            consoleLog += "Authentication request failed with User ID " + userid;
            request.getSession().setAttribute("consolelog", consoleLog);
            redirectPage(request, response, "/login.jsp");
            return;
        }
        /* Read the output returned from the authentication */

        code = Integer.parseInt(responseMap.get("code"));
        Gson gson = new Gson();

        if (code == 0) {
            consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                    : request.getSession().getAttribute("consolelog").toString();
            consoleLog += "<br>" + format.format(new Date()) + " : ";
            if (mode.equals("2")) {//Authenticate SMS
                consoleLog += " SMS Token Code validation success";
            } else if (mode.equals("3")) {//Authenticate OTP
                consoleLog += " OTP Token Code validation success";
            }
            request.getSession().setAttribute("consolelog", consoleLog);

            String authJson = responseMap.get("object");
            HashMap<String, String> authMap = gson.fromJson(authJson, HashMap.class);

            multiStepAuth = authMap.get("multiStepAuth");
            authMethods = authMap.get("authMethods");
            adaptiveScore = authMap.get("adaptiveScore");
            authToken = authMap.get("authToken");
            secretCode= authMap.get("secretCode");
            /* STORED SESSION */
            request.getSession().setAttribute("successMsg", "Login Successful");
            request.getSession().setAttribute("returnCode", "0");
            request.getSession().setAttribute("userid", userid);
            request.getSession().setAttribute("userName", userName);
            request.getSession().setAttribute("password", password);
            request.getSession().setAttribute("multiStepAuth", multiStepAuth);
            request.getSession().setAttribute("authToken", authToken);
            request.getSession().setAttribute("secretCode", secretCode);
            request.getSession().setAttribute("adaptiveScore", adaptiveScore);
            request.getSession().setAttribute("authMethods", authMethods);

            if (multiStepAuth.equals("true")) {
                request.getSession().setAttribute("smsEnabled", "true");
                request.getSession().setAttribute("otpEnabled", "true");
                request.getSession().setAttribute("crOtpEnabled", "true");
                request.getSession().setAttribute("pkiEnabled", "true");
                request.getSession().setAttribute("qnaEnabled", "true");
                
                List<String> availAuthList = new ArrayList<String>();
                availAuthList.addAll(Arrays.asList(authMethods.split(",")));
                
                if (availAuthList.contains("SMS")) {
                    request.getSession().setAttribute("smsEnabled", "false");
                } 
                
                if (availAuthList.contains("PKI")) {
                    request.getSession().setAttribute("pkiEnabled", "false");
                } 
                
                if (availAuthList.contains("OTP")) {
                    request.getSession().setAttribute("otpEnabled", "false");
                } 
                
                if (availAuthList.contains("CROTP")) {
                    request.getSession().setAttribute("crOtpEnabled", "false");
                } 
                
                if (availAuthList.contains("QNA")) {
                    request.getSession().setAttribute("qnaEnabled", "false");
                } 

//                    else // for testing 
//                        request.getSession().setAttribute("smsEnabled", "true");
                request.getSession().removeAttribute("authCode");
                if (pageid != null && pageid.equals("multistep")) {
                    request.getSession().setAttribute("loginSession", "1");
                    /* STORED SESSION */
                    redirectPage = "/main.jsp";

                    consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                            : request.getSession().getAttribute("consolelog").toString();
                    consoleLog += "<br>" + format.format(new Date()) + " : ";
                    consoleLog += " Login success";
                    request.getSession().setAttribute("consolelog", consoleLog);
                } else {
                    request.getSession().setAttribute("displayAlert", "Y");
                    redirectPage = "/multiStep.jsp";
                }
            } else if (multiStepAuth.equals("blocked")) {
                request.getSession().setAttribute("returnMsg", "Login is not allowed. Risk is detected on your login.");
                request.getSession().removeAttribute("userid");
                request.getSession().removeAttribute("password");
                request.getSession().removeAttribute("successMsg");
                request.getSession().removeAttribute("returnCode");
                request.getSession().removeAttribute("authMode");
                request.getSession().removeAttribute("authCode");
                request.getSession().removeAttribute("crOtpChallenge");
                request.getSession().removeAttribute("multiStep");
                request.getSession().removeAttribute("authToken");
                request.getSession().removeAttribute("qnaQues");
                request.getSession().removeAttribute("quesSize");
                request.getSession().removeAttribute("secretCode");

                redirectPage = "/login.jsp";
            } else {
                request.getSession().setAttribute("loginSession", "1");
                redirectPage = "/main.jsp";

                consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                        : request.getSession().getAttribute("consolelog").toString();
                consoleLog += "<br>" + format.format(new Date()) + " : ";
                consoleLog += " Login success";
                request.getSession().setAttribute("consolelog", consoleLog);
            }

            redirectPage(request, response, redirectPage);
            return;
        } else {
            if (mode.equals("3")) {
                request.getSession().setAttribute("returnMsg", "Invalid OTP code");
            } else {
                request.getSession().setAttribute("returnMsg", responseMap.get("message"));
            }

            request.getSession().removeAttribute("userid");
            request.getSession().removeAttribute("password");
            request.getSession().removeAttribute("successMsg");
            request.getSession().removeAttribute("returnCode");
            request.getSession().removeAttribute("authMode");
            request.getSession().removeAttribute("authCode");
            request.getSession().removeAttribute("crOtpChallenge");
            request.getSession().removeAttribute("multiStep");
            request.getSession().removeAttribute("authToken");

            redirectPage(request, response, "/login.jsp");
            return;
        }

    }

    private void reqAuth(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String userid = request.getParameter("userid");
        String password = request.getParameter("password");
        String authReq = request.getParameter("REQ");
        String multiStep = request.getParameter("multiStep");
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        String consoleLog = "";

        APIController apiController = new APIController();
        HashMap<String, String> responseMap = new HashMap();

        if (authReq.equals("2")) {//Request SMS Code
            consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                    : request.getSession().getAttribute("consolelog").toString();
            consoleLog += "<br>" + format.format(new Date()) + " : ";
            consoleLog += " Starting to request SMS Token Code...";
            request.getSession().setAttribute("consolelog", consoleLog);
        }

        if (authReq.equals("5")) {//Request CR challenge
            consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                    : request.getSession().getAttribute("consolelog").toString();
            consoleLog += "<br>" + format.format(new Date()) + " : ";
            consoleLog += " Starting to request CR challenge Code...";
            request.getSession().setAttribute("consolelog", consoleLog);
        }

        if (authReq.equals("7")) {//Request Qna Question
            consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                    : request.getSession().getAttribute("consolelog").toString();
            consoleLog += "<br>" + format.format(new Date()) + " : ";
            consoleLog += " Starting to request Qna Questions...";
            request.getSession().setAttribute("consolelog", consoleLog);
        }        

        responseMap = apiController.RequestOTP(getUserLoginName(userid), password, authReq, "", ipAddress, userAgent, "");
        if (responseMap != null && !responseMap.isEmpty() && !authReq.equals("7")) {
            String authJson = responseMap.get("object");
            Gson gson = new Gson();
            HashMap<String, String> authMap = gson.fromJson(authJson, HashMap.class);
            int code = Integer.parseInt(responseMap.get("code"));
            if (code == 0) {
                if (authReq.equals("2")) {//Success Request SMS Code
                    consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                            : request.getSession().getAttribute("consolelog").toString();
                    consoleLog += "<br>" + format.format(new Date()) + " : ";
                    consoleLog += " Request SMS code successful";
                    request.getSession().setAttribute("consolelog", consoleLog);
                }
                if (authReq.equals("5")) {//Success Request Cr challenge
                    consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                            : request.getSession().getAttribute("consolelog").toString();
                    consoleLog += "<br>" + format.format(new Date()) + " : ";
                    consoleLog += " Request challenge code successful";
                    request.getSession().setAttribute("consolelog", consoleLog);
                }
//                    if (authReq.equals("7")) {//Success Request Cr challenge
//                        consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
//                                : request.getSession().getAttribute("consolelog").toString();
//                        consoleLog += "<br>" + format.format(new Date()) + " : ";
//                        consoleLog += " Request questions successful";
//                        request.getSession().setAttribute("consolelog", consoleLog);
//                    }
                /* STORED SESSION */
                request.getSession().setAttribute("successMsg", "Login Successful");
                request.getSession().setAttribute("authCode", "0");
                request.getSession().setAttribute("userid", userid);
                request.getSession().setAttribute("password", password);
                request.getSession().setAttribute("authMode", authReq);
                request.getSession().setAttribute("displayString", "SMS Token Code:");
                if (authReq.equals("5")) {
                    request.getSession().setAttribute("crOtpChallenge", authMap.get("otpChallenge"));
                    request.getSession().setAttribute("displayString", "CR OTP Token:");
                }
//                    if(authReq.equals("7"))
//                    {
//                        request.getSession().setAttribute("qnaQues", authMap.get("otpChallenge"));
//                        
//                    }
            } else if (authReq.equals("5")) {
                request.getSession().setAttribute("returnMsg", "Challenge Code request failed");
            } else {
                request.getSession().setAttribute("returnMsg", "SMS Code request failed");
                consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                        : request.getSession().getAttribute("consolelog").toString();
                consoleLog += "<br>" + format.format(new Date()) + " : ";
                consoleLog += " SMS Code request failed";
                request.getSession().setAttribute("consolelog", consoleLog);
            }
        } else if (responseMap != null && !responseMap.isEmpty() && authReq.equals("7")) {

            String authJson = responseMap.get("object");
            Gson gson = new Gson();
            ArrayList<LinkedTreeMap<String, String>> questions = gson.fromJson(authJson, ArrayList.class);
            int code = Integer.parseInt(responseMap.get("code"));

            if (code == 0) {
                //Success Request Qna 
                int quesSize = questions.size();
//                String[] quesId = new String[5];
//                String[] quesDisplay = new String[5];
//                int i = 0 ;
//                   
//                for ( LinkedTreeMap<String , String> question : questions )
//                {
//                    quesId[i]=question.get ( "id" );
//                    quesDisplay[i]=question.get ( "question" );
//                    i++;
//                }
                consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                        : request.getSession().getAttribute("consolelog").toString();
                consoleLog += "<br>" + format.format(new Date()) + " : ";
                consoleLog += " Request questions successful";
                request.getSession().setAttribute("consolelog", consoleLog);
                request.getSession().setAttribute("successMsg", "Login Successful");
                request.getSession().setAttribute("authCode", "0");
                request.getSession().setAttribute("userid", userid);
                request.getSession().setAttribute("password", password);
                request.getSession().setAttribute("authMode", authReq);
                request.getSession().setAttribute("quesSize", quesSize + "");
                // request.getSession().setAttribute("quesId", quesId);
                // request.getSession().setAttribute("quesDisplay", quesDisplay);

                request.getSession().setAttribute("qnaQues", questions);

            }

        } else if (authReq.equals("5")) {
            request.getSession().setAttribute("returnMsg", "Challenge Code request failed");
        } else {
            request.getSession().setAttribute("returnMsg", "SMS Code request failed");
            consoleLog = (null == request.getSession().getAttribute("consolelog")) ? null
                    : request.getSession().getAttribute("consolelog").toString();
            consoleLog += "<br>" + format.format(new Date()) + " : ";
            consoleLog += " SMS Code request failed";
            request.getSession().setAttribute("consolelog", consoleLog);
        }
        if (multiStep != null && multiStep.equals("true")) {
            redirectPage(request, response, "/multiStep.jsp");
        } else {
            redirectPage(request, response, "/login.jsp");
        }
    }

    private void redirectPage(HttpServletRequest request, HttpServletResponse response, String redirectPage)
            throws ServletException, IOException {

        RequestDispatcher requestDispatcher = request.getRequestDispatcher(redirectPage);
        requestDispatcher.forward(request, response);
    }

    private String getUserLoginName(String username) {
        String loginname = "";
        try {
            //    UserManagement user = new UserManagement();
            loginname = username;
        } catch (Exception e) {
        }
        return loginname;
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
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
        return "Short description";
    }// </editor-fold>

}
