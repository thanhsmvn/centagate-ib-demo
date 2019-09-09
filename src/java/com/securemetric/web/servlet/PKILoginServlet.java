package com.securemetric.web.servlet;

import com.securemetric.web.api.Pkcs7Auth;
import com.google.gson.Gson;
import com.securemetric.web.util.Config;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Properties;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.binary.Hex;

/**
 *
 * @author SecureMetric Technology Sdn. Bhd.
 */
public class PKILoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private PrintWriter out;
    private HashMap<String, String> returnData;
    private SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("M/dd/yyyy, hh:mm:ss a");

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
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(response, request);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        this.processRequest(resp, req);
    }
    
    

    private void processRequest(HttpServletResponse response, HttpServletRequest request) throws IOException {
        response.setContentType("text/html;charset=utf-8");
        String authReq = request.getParameter("REQ");
        String consolelog = request.getParameter("consolelog");
        out = response.getWriter();
        try {
            Gson gson = new Gson();

            String ipAddress = request.getRemoteAddr();;
            String userAgent = request.getHeader("User-Agent");

            String username = request.getParameter("username");
            String plainText = request.getParameter("plainText");
            String signature = request.getParameter("signature");
            String algo = "0";
            System.out.println(plainText);
            System.out.println("Signature   " + signature);
            signature = this.convertWebSafeBase64ToNormalBase64(signature);
            
            Date d = new Date();
            Pkcs7Auth pkcs7Auth = new Pkcs7Auth();
            plainText = this.convertWebSafeBase64ToNormalBase64(plainText);
            HashMap<String, String> responseMap = pkcs7Auth.Authenticate(username, plainText, signature, algo, "", ipAddress, userAgent);
//            consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "PKI Login Successfully";
//            consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "Transaction Complete Successful";   
//            request.getSession().setAttribute("consolelog", consolelog);
            if (responseMap != null && !responseMap.isEmpty()) {
                String authJson = responseMap.get("object");
                HashMap<String, String> authMap = gson.fromJson(authJson, HashMap.class);
                int code = Integer.parseInt(responseMap.get("code"));
                if (code == 0) {
                    request.getSession().setAttribute("successMsg", "PKI Authentication Successful");
                    request.getSession().setAttribute("authCode", "0");
                    request.getSession().setAttribute("authMode", authReq);
                    request.getSession().setAttribute("authObMethod", "PKI");
                    request.getSession().setAttribute("authToken", "");

                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "PKI Authentication Successfully";
                    request.getSession().setAttribute("consolelog", consolelog);
                } else {

                    consolelog = consolelog + "<br>" + DATE_FORMAT.format(d) + " : " + "PKI Authentication Failed";
                    consolelog = consolelog + "<br> Reason" + DATE_FORMAT.format(d) + " : " + responseMap.get("message");
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
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            out.close();
        }
    }

    private String convertWebSafeBase64ToNormalBase64(String websafeBase64) {
        return websafeBase64.replaceAll("\\-", "+").replaceAll("_", "/") + "===".substring(0, (3 * websafeBase64.length()) % 4);
    }

    private String calculateFingerprintSha1(X509Certificate certificate) throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        byte[] der = certificate.getEncoded();
        md.update(der);
        byte[] digest = md.digest();

        return Hex.encodeHexString(digest);
    }

    private void redirectToUnsecuredPort(HttpServletRequest request, HttpServletResponse response, String errorMessage)
            throws IOException {
        /*
         * Invalidate the session
         */
        request.getSession().invalidate();
        Config config = new Config();
        Properties sysProp = config.getConfig(Config.TYPE_SYSTEM);
        // ResourceBundle resource = ResourceBundle.getBundle("system");

        String insecureLoginUrl = sysProp.getProperty(Config.LOGIN_URL);//resource.getString("login-url-no-client-auth");
        insecureLoginUrl = insecureLoginUrl.concat("?err=" + errorMessage);

        response.setContentType("text/html;charset=UTF-8");
        request.setCharacterEncoding("utf-8");
        PrintWriter writer = response.getWriter();
        writer.write("<html><head><title>CENTAGATE</title></head><body>");
        writer.write("<script type=\"text/javascript\">\n");
        writer.write("    if ( document.execCommand )\n");
        writer.write("        document.execCommand ( \"ClearAuthenticationCache\" ) ;\n");
        writer.write("    if ( window.crypto && window.crypto.logout )\n");
        writer.write("        window.crypto.logout ( ) ;\n\n");
        writer.write("    document.location = \"" + insecureLoginUrl + "\" ;");
        writer.write("</script></body></html>");
        writer.flush();
        writer.close();
    }

    private void redirectPage(HttpServletRequest request, HttpServletResponse response, String redirectPage)
            throws ServletException, IOException {
        RequestDispatcher requestDispatcher = request.getRequestDispatcher(redirectPage);
        requestDispatcher.forward(request, response);
    }

}
