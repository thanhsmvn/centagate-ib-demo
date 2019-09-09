/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.securemetric.web.servlet;

import com.google.gson.Gson;
import com.securemetric.web.api.APIController;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * @author auyong
 */
public class TransServlet extends HttpServlet {

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

        request.setCharacterEncoding("UTF-8");
        String redirectPage = "/main.jsp";
        try {

            String mode = request.getParameter("MODE");
            String authReq = request.getParameter("REQ");

            if (mode != null && mode.equals("CLEAR")) {
                request.getSession().removeAttribute("userid");
                request.getSession().removeAttribute("password");
                request.getSession().removeAttribute("successMsg");
                request.getSession().removeAttribute("returnCode");
                request.getSession().removeAttribute("authMode");
                request.getSession().removeAttribute("authCode");
                request.getSession().removeAttribute("otpChallenge");
                redirectPage(request, response, redirectPage);
            }
            //processAmount(request, response);
            if (authReq != null && authReq.equals("1")) {               
                this.regenAuthToken(request, response);               
            } else if (authReq != null && !authReq.equals("1")) // SMS TAC or CRTAC Request            
            {              
                System.out.println("**********AAAAAAAAAAA***********");
                this.reqAuth(request, response);                
            } else //TAC Authentication
            if (mode.equals("2") || mode.equals("3") || mode.equals("4") || mode.equals("5") || mode.equals("9")) {                
                this.authTran(request, response);                
            }
        } catch (Exception e) {
            System.out.println("DEBUG Message[TransServlet] : Failed with exception : " + e.getMessage());
            e.printStackTrace();
        }

    }

    /***
     * This method will check authentication method based on the amount
     
     <5M: enable all methods
     5-50M: not allow SMS authentication
     50-200M: not allow SMS, OTP, Mobile Push
     >200M: only PKI
       
     * @param request
     * @param response
     * @throws ServletException
     * @throws IOException 
     */
    private void processAmount(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {  
        request.setCharacterEncoding("UTF-8");
        String redirectPage = "/main.jsp";
        String consolelog = (String) request.getSession().getAttribute("consolelog");
        Date d = new Date();
        SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("M/dd/yyyy, hh:mm:ss a");
        String amt = request.getParameter("amt");
        String authReq = request.getParameter("REQ");
        boolean allowed = true;
        try {
            if (authReq != null && amt != null) {
                float amount = Float.parseFloat(amt);
                if ((amount >= 5000000 && amount < 50000000) && authReq.equals("2")) {
                    allowed = false;
                }
                if ((amount >= 50000000 && amount < 200000000) && (authReq.equals("2") || authReq.equals("3") || authReq.equals("8"))) {
                    allowed = false;
                }
                if ((amount >= 200000000) && !authReq.equals("6")) {
                    allowed = false;
                }
            }
        } catch (NumberFormatException nfe){            
        }
        if (!allowed) {
            consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "Process is not allowed";
            request.getSession().setAttribute("consolelog", consolelog);
            response.sendRedirect(redirectPage);
            return;
        }
    }
    
    
    /***
     * This method will perform:
        - check TAC authentication
        - do transaction
        - return status: 0-Success, 1 or others -Failed
        
        
     * @param request
     * @param response
     * @throws ServletException
     * @throws IOException 
     */
    private void authTran(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {        
        String mode = request.getParameter("MODE");
        String userid = (String) request.getSession().getAttribute("userid");
        String tac = request.getParameter("tac");
        String challenge = (String) request.getSession().getAttribute("otpChallenge");
        String passAuthToken = (String) request.getSession().getAttribute("authToken");
        String qrPlainText = (String) request.getSession().getAttribute("qrPlainText");
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        String returnStatus = "";
        String browserFp = request.getParameter("browserfp");

        String consolelog = (String) request.getSession().getAttribute("consolelog");
        Date d = new Date();
        SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("M/dd/yyyy, hh:mm:ss a");

        int code = 1;

        APIController apiController = new APIController();
        HashMap<String, String> responseMap = new HashMap();
        responseMap = apiController.Transaction(getUserLoginName(userid), mode, tac, challenge, passAuthToken, qrPlainText, ipAddress, userAgent, browserFp);

        /* Read the output returned from the authentication */
        if (responseMap != null && !responseMap.isEmpty()) {
            code = Integer.parseInt(responseMap.get("code"));
        //    System.out.println("$$$$$$$$$$$$$$$$$: "+code );
            if (code == 0) {
                /* TODO output your page here. You may use following sample code. */
                consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "Transaction Complete Successful";
                request.getSession().setAttribute("successMsg", "Transaction Complete Successful");
                request.getSession().setAttribute("returnCode", "0");
                returnStatus = "0";
            } else {
                consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "Transaction Failed";
                consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "TAC authorization failed with User ID " + userid;
                consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "Reason: " + responseMap.get("message");
                request.getSession().setAttribute("returnMsg", responseMap.get("message"));
                returnStatus = "1";
            }
        } else {

            consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "Transaction Failed";
            consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "TAC authorization failed with User ID " + userid;
            consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "Reason: No output returned from the authentication";
            request.getSession().setAttribute("returnMsg", "TAC authorization failed with User ID " + userid);
            returnStatus = "1";
        }

        request.getSession().setAttribute("consolelog", consolelog);
        response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(returnStatus);
    }

    private void reqAuth(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {        
        request.setCharacterEncoding("UTF-8");
        String authReq = request.getParameter("REQ");
        String userid = (String) request.getSession().getAttribute("userid");
        String password = (String) request.getSession().getAttribute("password");
        String authToken = (String) request.getSession().getAttribute("authToken");
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        String amt = request.getParameter("amt");
        String fromacct = request.getParameter("fromacct");
        String toacc = request.getParameter("toacc");
        String effdate = request.getParameter("effdate");
        String recmail = request.getParameter("recmail");
        String desc = request.getParameter("desc");

        String details = "Transaction from " + fromacct + " to " + toacc
                + "\nAmount : " + amt
                + "\nEffective Date :" + effdate;

        if (recmail != null && recmail.length() > 0) {
            details = details + "\nRecipient email :" + recmail;
        }

        if (desc != null && desc.length() > 0) {
            details = details + "\nDescription :" + desc;
        }
        
        APIController apiController = new APIController();
        HashMap<String, String> responseMap = new HashMap();
        String consolelog = request.getParameter("consolelog");
        Date d = new Date();
        SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("M/dd/yyyy, hh:mm:ss a");
        if (details != null && details.trim().length() > 0) {
            consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + details.replaceAll("(\r|\n)", "<br>" + DATE_FORMAT.format(d) + " : ");
        }
        
        if (authReq.equals("4")){

            String qrCode = "";
            String qrOtpChallenge = "";
            String qrPlainText = "";

            responseMap = apiController.RequestOTP(getUserLoginName(userid), password, authReq, authToken, ipAddress, userAgent, details);
            System.out.println("**************" + responseMap);
            System.out.println("**************" + responseMap.get("code"));
            
            if (responseMap != null && !responseMap.isEmpty()) {
                String authJson = responseMap.get("object");
                Gson gson = new Gson();
                HashMap<String, String> authMap = gson.fromJson(authJson, HashMap.class);
                
                int code = Integer.parseInt(responseMap.get("code"));
                
                if (code == 0) {

                    qrCode = authMap.get("qrCode");
                    qrOtpChallenge = authMap.get("otpChallenge");
                    qrPlainText = authMap.get("plainText");

                    /* TODO output your page here. You may use following sample code. */
                    request.getSession().setAttribute("successMsg", "Login Successful");
                    request.getSession().setAttribute("authCode", "0");
                    request.getSession().setAttribute("authMode", authReq);
                    request.getSession().setAttribute("qrCode", qrCode);
                    request.getSession().setAttribute("qrPlainText", qrPlainText);
                    request.getSession().setAttribute("authObMethod", "QRCODE");
                    request.getSession().setAttribute("authToken", authMap.get("authToken"));

                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "QR Code Request Successfully";
                    request.getSession().setAttribute("consolelog", consolelog);

//                    if (authReq.equals("3")) {
//                        request.getSession().setAttribute("otpChallenge", authMap.get("otpChallenge"));
//                        response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
//                        response.setCharacterEncoding("UTF-8");
//                        response.getWriter().write(authMap.get("otpChallenge"));
//                    } else {

                        request.getSession().setAttribute("otpChallenge", qrOtpChallenge);
                        response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
                        response.setCharacterEncoding("UTF-8");
                        
                            //adding otpchallenge to response with delimiter "||"
                        String qrRespondWithChallenge = qrCode + "||" + qrOtpChallenge;
                        response.getWriter().write(qrRespondWithChallenge);
                        System.out.println(qrPlainText);
                        System.out.println(qrOtpChallenge);
                        System.out.println(qrCode);
                        System.out.println(qrRespondWithChallenge);
//                    }
                } else {

                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "QR Code Request Failed";
                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + responseMap.get("message");
                    request.getSession().setAttribute("consolelog", consolelog);

                    response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write("error");
                }
            } else {
                consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "QR Code Request Failed";
                request.getSession().setAttribute("consolelog", consolelog);
                response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
                response.setCharacterEncoding("UTF-8");
                response.getWriter().write("error");
            }
        } else if (authReq.equals("8")){
            
            
            responseMap = apiController.RequestOTP(getUserLoginName(userid), password, authReq, authToken, ipAddress, userAgent, details);
            if (responseMap != null && !responseMap.isEmpty()) {
                String authJson = responseMap.get("object");
                Gson gson = new Gson();
                HashMap<String, String> authMap = gson.fromJson(authJson, HashMap.class);

                int code = Integer.parseInt(responseMap.get("code"));
                if (code == 0) {
                    request.getSession().setAttribute("successMsg", "Login Successful");
                    request.getSession().setAttribute("authCode", "0");
                    request.getSession().setAttribute("authMode", authReq);
                    request.getSession().setAttribute("authObMethod", "CROTP");
                    request.getSession().setAttribute("authToken", authMap.get("authToken"));

                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "Mobile Push Request Successfully";
                    request.getSession().setAttribute("consolelog", consolelog);
                } else {

                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "Mobile Push Request Failed";
                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + responseMap.get("message");
                    request.getSession().setAttribute("consolelog", consolelog);

                    response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write("error");
                }
            } else {
                consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "Mobile Push Request Failed";
                request.getSession().setAttribute("consolelog", consolelog);
                response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
                response.setCharacterEncoding("UTF-8");
                response.getWriter().write("error");
            }
            
            
         } else if (authReq.equals("2")) {
            responseMap = apiController.RequestOTP(getUserLoginName(userid), password, authReq, authToken, ipAddress, userAgent, details);
            if (responseMap != null && !responseMap.isEmpty()) {               

                int code = Integer.parseInt(responseMap.get("code"));
                if (code == 0) {
                    request.getSession().setAttribute("successMsg", "SMS Request Successful");
                    request.getSession().setAttribute("authCode", "0");
                    request.getSession().setAttribute("authMode", authReq);
                    request.getSession().setAttribute("authObMethod", "SMS");
                    request.getSession().setAttribute("authToken", "");

                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "SMS Request Successfully";                    
                    request.getSession().setAttribute("consolelog", consolelog);
                } else {

                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "SMS Request Failed";
                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + responseMap.get("message");
                    request.getSession().setAttribute("consolelog", consolelog);

                    response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write("error");
                }
            } else {
                consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "SMS Request Failed";
                request.getSession().setAttribute("consolelog", consolelog);
                response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
                response.setCharacterEncoding("UTF-8");
                response.getWriter().write("error");
            }
        } else if (authReq.equals("3")) {
            responseMap = apiController.RequestOTP(getUserLoginName(userid), password, authReq, authToken, ipAddress, userAgent, details);
            if (responseMap != null && !responseMap.isEmpty()) {               

                int code = Integer.parseInt(responseMap.get("code"));
                if (code == 0) {
                    request.getSession().setAttribute("successMsg", "OTP Request Successful");
                    request.getSession().setAttribute("authCode", "0");
                    request.getSession().setAttribute("authMode", authReq);
                    request.getSession().setAttribute("authObMethod", "OTP");
                    request.getSession().setAttribute("authToken", "");

                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "OTP Request Successfully";
                    request.getSession().setAttribute("consolelog", consolelog);
                } else {

                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "OTP Request Failed";
                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + responseMap.get("message");
                    request.getSession().setAttribute("consolelog", consolelog);

                    response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write("error");
                }
            } else {
                consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "OTP Request Failed";
                request.getSession().setAttribute("consolelog", consolelog);
                response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
                response.setCharacterEncoding("UTF-8");
                response.getWriter().write("error");
            }    
        } else if (authReq.equals("9")){
            responseMap = apiController.RequestOTP(getUserLoginName(userid), password, authReq, authToken, ipAddress, userAgent, details);
            if (responseMap != null && !responseMap.isEmpty()){
                String authJson1 = responseMap.get("object");
                Gson gson = new Gson();
                HashMap<String, String> authMap = gson.fromJson(authJson1, HashMap.class);
                int code = Integer.parseInt(responseMap.get("code"));
                if (code == 0) {
                    String signingChallenge = authMap.get("otpChallenge");
                    request.getSession().setAttribute("successMsg", "SigningOTP Request Successful");
                    request.getSession().setAttribute("authCode", "0");
                    request.getSession().setAttribute("authMode", authReq);
                    request.getSession().setAttribute("authObMethod", "SigningOTP");
                    request.getSession().setAttribute("authToken", "");
                    request.getSession().setAttribute("otpChallenge", signingChallenge);
                    
                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "SigningOTP Request Successfully";
                    request.getSession().setAttribute("consolelog", consolelog);
                    response.setContentType("text/plain");
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write(signingChallenge);
                } else{
                    
                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "SigningOTP Request Failed";
                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + responseMap.get("message"); 
                    request.getSession().setAttribute("consolelog", consolelog);
                    
                    response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write("error");
                }
            }else {
                consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "SigningOTP Request Failed";
                request.getSession().setAttribute("consolelog", consolelog);
                response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
                response.setCharacterEncoding("UTF-8");
                response.getWriter().write("error");
            }            
        } else if (authReq.equals("5")) {
            responseMap = apiController.RequestOTP(getUserLoginName(userid), password, authReq, authToken, ipAddress, userAgent, details);
            if (responseMap != null && !responseMap.isEmpty()) {               
                String authJson = responseMap.get("object");
                Gson gson = new Gson();
                HashMap<String, String> authMap = gson.fromJson(authJson, HashMap.class);
                int code = Integer.parseInt(responseMap.get("code"));
                if (code == 0) {
                    String crOtpChallenge = authMap.get("otpChallenge");
                    request.getSession().setAttribute("successMsg", "CROTP Request Successful");
                    request.getSession().setAttribute("authCode", "0");
                    request.getSession().setAttribute("authMode", authReq);
                    request.getSession().setAttribute("authObMethod", "CROTP");
                    //request.getSession().setAttribute("authToken", authMap.get("authToken"));
                    request.getSession().setAttribute("authToken", "");
                    request.getSession().setAttribute("otpChallenge",crOtpChallenge);

                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "CROTP Request Successfully";
                    request.getSession().setAttribute("consolelog", consolelog);
                    response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write(crOtpChallenge);
                } else {

                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "CROTP Request Failed";
                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + responseMap.get("message");
                    request.getSession().setAttribute("consolelog", consolelog);

                    response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write("error");
                }
            } else {
                consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "CROTP Request Failed";
                request.getSession().setAttribute("consolelog", consolelog);
                response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
                response.setCharacterEncoding("UTF-8");
                response.getWriter().write("error");
            }
        } else if (authReq.equals("6")) {
            consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "PKI Login Successfully";
            consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "Transaction Complete Successful";   
            request.getSession().setAttribute("consolelog", consolelog);
        }
    }

    private void regenAuthToken(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String userid = request.getParameter("userid");
        String password = (String) request.getSession().getAttribute("password");
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        String browserFp = request.getParameter("browserfp");

        String returnStatus = "";
        APIController apiController = new APIController();
        HashMap<String, String> responseMap = new HashMap();
        responseMap = apiController.Authenticate(getUserLoginName(userid), password, "1", "", "", "", ipAddress, userAgent, browserFp, "", 0, null);
        int code = 1;
        if (responseMap.isEmpty()) {
            request.getSession().setAttribute("returnMsg", "Authentication request failed with User ID " + userid);
            request.getSession().invalidate();
            returnStatus = "1";
        } else {

            code = Integer.parseInt(responseMap.get("code"));
            /* Read the output returned from the authentication */
            if (code == 0) {
                String authJson = responseMap.get("object");
                Gson gson = new Gson();
                HashMap<String, String> authMap = gson.fromJson(authJson, HashMap.class);
                request.getSession().invalidate();
                request.getSession().setAttribute("authToken", authMap.get("authToken"));
                request.getSession().setAttribute("userid", userid);
                request.getSession().setAttribute("password", password);
                request.getSession().setAttribute("secretCode", authMap.get("secretCode"));
                request.getSession().setAttribute("loginSession", "1");
                returnStatus = "0";

            } else {
                request.getSession().invalidate();
                returnStatus = "1";
            }
        }
        response.setContentType("text/plain");  // Set content type of the response so that jQuery knows what it can expect.
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(returnStatus);
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
            System.out.println("DEBUG Message[getUserLoginName] : Failed with exception : " + e.getMessage());
            e.printStackTrace();
        }

        return loginname;
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /*
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

    /*
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

    /*
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
