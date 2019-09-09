<%@ page contentType="text/html;charset=UTF-8"%>
<%@ page language = "java" %>
<%@ page session= "true" %>
<%@ page import = "java.util.*" %>
<%@ page import = "com.google.gson.internal.LinkedTreeMap" %>
<%@ page import = "com.securemetric.web.util.Config"%>
<!DOCTYPE html>
<%
    //ResourceBundle resource = ResourceBundle.getBundle("system");
    Config sysConfig = new Config();
    Properties sysProp = sysConfig.getConfig(Config.TYPE_SYSTEM);
    String BaseURL = sysProp.getProperty(Config.BASE_URL);//resource.getString("baseurl");
    String authOption = sysProp.getProperty(Config.AUTH_OPTION);//resource.getString("authOption");
    
    String smsDisplay = "";
    String otpDisplay = "";
    String crOtpDisplay = "";
    String pkiDisplay = "";
    String qnaDisplay = "";

    String smsAuth = "";
    String crOtpAuth = "";
    String otpAuth = "";
    String pkiAuth = "";
    String qnaAuth = "";

    String loginSession = (String) request.getSession().getAttribute("loginSession");
    String returnCode = (String) request.getSession().getAttribute("returnCode");
    String authCode = (String) request.getSession().getAttribute("authCode");
    String errorMsg = (String) request.getSession().getAttribute("returnMsg");
    String consolelog = (String) request.getSession().getAttribute("consolelog");
    String userid = "";
    String password = "";
    String successMsg = "";
    String authMode = "";
    String crOtpChallenge = "******";
    String classStyle = "class=login-mandatory";
    String classStyle2 = "";
    String loginid = "asd";
    String displayLink = "";
    String displayString = (String) request.getSession().getAttribute("displayString");
    ArrayList<LinkedTreeMap<String, String>> questions = (ArrayList) request.getSession().getAttribute("qnaQues");
    //int quesSize = Integer.parseInt((String)request.getSession().getAttribute("quesSize"));
    String quesSize = (String) request.getSession().getAttribute("quesSize");
    int quesNum = 0;
    //String[] quesId = (String[])request.getSession().getAttribute("quesId");
    //String[] quesDisplay = (String[])request.getSession().getAttribute("quesDisplay");

    if (returnCode != null && returnCode.equals("0")) {
        classStyle = "readonly tabindex=-1 class=input-display ";
        userid = (String) request.getSession().getAttribute("userid");
        password = (String) request.getSession().getAttribute("password");
        loginid = (String) request.getSession().getAttribute("loginid");
        successMsg = (String) request.getSession().getAttribute("successMsg");
        smsAuth = (String) request.getSession().getAttribute("SMS");
        otpAuth = (String) request.getSession().getAttribute("OTP");
        crOtpAuth = (String) request.getSession().getAttribute("OTP");
        crOtpChallenge = (String) request.getSession().getAttribute("crOtpChallenge");
        pkiAuth = (String) request.getSession().getAttribute("PKI");
        qnaAuth = (String) request.getSession().getAttribute("QNA");

        displayLink = "class=hide-row";
    }

    if (authCode != null && authCode.equals("0")) {
        classStyle = "readonly tabindex=-1 class=input-display ";
        classStyle2 = "readonly tabindex=-1 disabled";
        userid = (String) request.getSession().getAttribute("userid");
        loginid = (String) request.getSession().getAttribute("loginid");
        password = (String) request.getSession().getAttribute("password");
        successMsg = (String) request.getSession().getAttribute("successMsg");
        authMode = request.getSession().getAttribute("authMode") != null ? (String) request.getSession().getAttribute("authMode") : "";
        crOtpChallenge = (String) request.getSession().getAttribute("crOtpChallenge");
        displayLink = "class=hide-row";
    }

    if (smsAuth == null) {
        smsDisplay = "style=\"visibility: hidden\"";
    }

    if (otpAuth == null) {
        otpDisplay = "style=\"visibility: hidden\"";
    }
    if (crOtpAuth == null) {
        crOtpDisplay = "style=\"visibility: hidden\"";
    }
    if (pkiAuth == null) {
        pkiDisplay = "style=\"visibility: hidden\"";
    }
    if (qnaAuth == null) {
        qnaDisplay = "style=\"visibility: hidden\"";
    }

    request.getSession().removeAttribute("returnMsg");

    if (consolelog == null) {
        consolelog = "Log Message";
        request.getSession().setAttribute("consolelog", "Log Message");
    }

%>

<HTML>
    <HEAD>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
        <TITLE>User Log-In</TITLE>
        <style type="text/css"><%@ include file="/styles/login.css" %></style>
        <style type="text/css"><%@ include file="/styles/styles.css" %></style>
        <script language="javascript" src="javascript/JSfunction.js"></script>
        <script language="javascript" src="javascript/JSFormat.js"></script>
        <script language="javascript" src="javascript/jquery-1.11.1.js"></script>
        <script language="javascript" src="javascript/jquery-ui-1.10.4.js"></script>
        <script type="text/javascript" src="javascript/fingerprint2.min.js"></script>
        <script language="javascript">
            d = new Date();

            var baseURL = getBaseURL();
            function setWINDOW()
            {

                if ('<%=loginSession%>' === '1') {
                    document.getElementById('fade').style.display = 'block';
                    document.getElementById('notice-message').style.display = 'block';
                    document.getElementById('notice-text').innerHTML = "Already Login";
                    setTimeout(function () {
                        window.location = (baseURL + "/selfregister.jsp");
                    }, 2000);
                } else {//User has not login yet.
                    if ('<%=returnCode%>' === '0' && '<%=authCode%>' !== '0')
                    {
                        //log = document.getElementById('consolelog').value;
                        // log = log + "<br>" + d.toLocaleString()+" : "+ "Username and password validation success";
                        // document.getElementById('consolelog').value =log;
                        // document.getElementById('displayconsolelog').innerHTML =log;

                        if ('<%=crOtpAuth%>' === '' || '<%=crOtpAuth%>' === 'null') {
                            document.getElementById('fade').style.display = 'block';
                            document.getElementById('notice-message').style.display = 'block';
                            document.getElementById('notice-text').innerHTML = "Mobile device not found. Please register your mobile";
                            setTimeout(function () {
                                window.location = (baseURL + "/registerdevice.jsp");
                            }, 2000);
                        }

                    }

                    if ('<%=authCode%>' === '0')
                    {
                        //log = document.getElementById('consolelog').value;
                        // log = log + "<br>" + d.toLocaleString()+" : "+ "Request SMS code successful";
                        //document.getElementById('consolelog').value =log;
                        // document.getElementById('displayconsolelog').innerHTML =log;
                        if ('<%=authMode%>' === '5') {

                            document.getElementById('input0').style.display = 'table-row';
                            document.getElementById("requestTokenTitleLogin").innerHTML = "CR OTP :"
                            document.getElementById('input1').style.display = 'table-row';
                            window.document.FORM.otp.className = "mandatory";

                        } else if ('<%=authMode%>' === '2') {
                            document.getElementById("requestTokenTitleLogin").innerHTML = "SMS OTP :"
                            document.getElementById('input1').style.display = 'table-row';
                            window.document.FORM.otp.className = "mandatory";
                        } else if ('<%=authMode%>' === '3') {
                            document.getElementById('input1').style.display = 'table-row';
                            window.document.FORM.otp.className = "mandatory";

                        } else if ('<%=authMode%>' === '7') {
                            document.getElementById('qnalist').style.display = 'table';
                        }

                    }



                    if ('<%=errorMsg%>' !== 'null') {
                        //log = document.getElementById('consolelog').value;
                        //log = log + "<br>" + d.toLocaleString()+" : "+ "Error : <%=errorMsg%>";
                        //document.getElementById('consolelog').value =log;
                        //document.getElementById('displayconsolelog').innerHTML =log;

                        document.getElementById('fade').style.display = 'block'
                        document.getElementById('error-message').style.display = 'block';
                        document.getElementById('error-text').innerHTML = '<%=errorMsg%>';
                        setTimeout(function () {
                            document.getElementById('error-message').style.display = 'none';
                            document.getElementById('fade').style.display = 'none';
                        }, 3000);
                    }
                }
            }

            function closeAlert()
            {
                document.getElementById('error-message').style.display = 'none';
                document.getElementById('fade').style.display = 'none';
            }

            function login(mode)
            {
                if (CheckMandatory(window.document.FORM) && mode === "1")
                {
                    window.document.FORM.userid.className = "input-display";
                    window.document.FORM.password.className = "input-display";

                    window.document.FORM.btnLogin.disabled = true;
                    window.document.FORM.btnClear.disabled = true;
                    window.document.FORM.action = baseURL + "/LoginServlet?MODE=" + mode;
                    window.document.FORM.submit();
                    return true;
                } else {
                    return false;
                }
            }

            function resetForm(mode) {

                window.document.FORM.action = baseURL + "/LoginServlet?MODE=" + mode;
                window.document.FORM.submit();
            }

            function authReq(req)
            {
                if (CheckMandatory(window.document.FORM))
                {
                    if ('<%=authOption%>' === 'Y') {
                        window.document.FORM.btnOTPLogin.disabled = true;
                    }

                    if (req === '3') {
                        document.getElementById("requestTokenTitleLogin").innerHTML = "OTP Token Code:"
                        document.getElementById("LoginAuthMode").value = '3';
                        window.document.FORM.btnSMSLogin.disabled = true;
                        document.getElementById('input1').style.display = 'table-row';
                        window.document.FORM.otp.className = "mandatory";
                        window.document.FORM.otp.focus();
                    }
                    if (req === '5') {

                        document.getElementById('input0').style.display = 'table-row';
                        document.getElementById("LoginAuthMode").value = '5';
                        window.document.FORM.btnSMSLogin.disabled = true;
                        document.getElementById('input1').style.display = 'table-row';
                        window.document.FORM.otp.className = "mandatory";
                        window.document.FORM.otp.focus();
                    }


                    if (req == '2') {

                        document.getElementById("requestTokenTitleLogin").innerHTML = "SMS OTP :"
                        window.document.FORM.action = baseURL + "/LoginServlet?REQ=" + req;
                        window.document.FORM.btnSMSLogin.disabled = true;
                        document.getElementById('input1').style.display = 'table-row';
                        window.document.FORM.otp.className = "mandatory";
                        window.document.FORM.otp.focus();

                        window.document.FORM.submit();

                    }

                    if (req == '5') {
                        document.getElementById("requestTokenTitleLogin").innerHTML = "CR OTP:"
                        window.document.FORM.action = baseURL + "/LoginServlet?REQ=" + req;

                        window.document.FORM.btnSMSLogin.disabled = true;
                        document.getElementById('input1').style.display = 'table-row';
                        window.document.FORM.otp.className = "mandatory";
                        window.document.FORM.otp.focus();
                        window.document.FORM.submit();
                    }

                    if (req == '7') {
                        window.document.FORM.btnSMSLogin.disabled = true;
                        window.document.FORM.action = baseURL + "/LoginServlet?REQ=" + req;
                        window.document.FORM.submit();
                    }
                } else
                {
                    return;
                }
            }

            function authLogin()
            {
                var mode = document.getElementById("LoginAuthMode").value;
                if (CheckMandatory(window.document.FORM))
                {
                    window.document.FORM.btnAuthLogin.disabled = true;
                    window.document.FORM.action = baseURL + "/LoginServlet?MODE=" + mode;
                    window.document.FORM.submit();
                }
            }

            function pkiLogin()
            {
                var mode = '6';

                var secureLoginUrl = baseURL + "/PKILoginServlet?MODE=" + mode;
                if (CheckMandatory(window.document.FORM))
                {
                    window.document.FORM.btnAuthLogin.disabled = true;
                    //	window.document.FORM.action = baseURL+"/LoginServlet?MODE="+mode;
                    secureLoginUrl = secureLoginUrl + "&userid=" + '<%=userid%>';
                    document.getElementById('FORM').method = "get";
                    if (document.getElementById("browserfp")) {
                        secureLoginUrl = secureLoginUrl + "&browserfp=" + document.getElementById("browserfp").value;
                    }
                    //        document.location = baseURL + "/PKILoginServlet?MODE="+mode+"&userid=test2a";
                    document.location = secureLoginUrl;
                    //	window.document.FORM.submit();	 	
                }
            }

            function getBaseURL() {

                var url = location.href;  // entire url including querystring - also: window.location.href;
                var baseURL = url.substring(0, url.indexOf('/', 14));


                if (baseURL.indexOf('http://localhost') !== -1) {
                    // Base Url for localhost
                    var url = location.href;  // window.location.href;
                    var pathname = location.pathname;  // window.location.pathname;
                    var index1 = url.indexOf(pathname);
                    var index2 = url.indexOf("/", index1 + 1);
                    var baseLocalUrl = url.substr(0, index2);

                    return baseLocalUrl;
                } else {
                    // Root Url for domain name
                    return baseURL + "/j2ee";
                }
            }

            function goToPage(page) {
                window.location = (baseURL + "/" + page);
            }

        </script>

    </HEAD>

    <FORM id="FORM" name="FORM" method="post" action="login.jsp">
        <input type="hidden" id="browserfp" name="browserfp" value="" />

        <BODY onload="setWINDOW();document.FORM.userid.focus()" style="background-position: center center; background-repeat: no-repeat">
            <script type="text/javascript">
                new Fingerprint2().get(function (result, components) {
                    $("#browserfp").val(result);
                });
            </script>

            <table cellpadding=0 cellspacing=0 border=0 width="100%">
                <tr><td colspan=2>
                        <table cellpadding=0 cellspacing=0 border=0 width="100%">

                            <tr>
                                <td class=login-body width="40%" align=center colspan="3">Enterprise Solution for Global Banking</td>
                            </tr>
                        </table>
                    </td></tr>

                <tr>
                    <!--<td width=280>-->

                    <td colspan=2>

                        <TABLE cellSpacing=0 cellPadding=1 width="100" align=center border=0 bordercolor="#FFFFFF" bordercolorlight="#eeeeee" bordercolordark="#ffffff">
                            <TBODY>
                                <tr>&nbsp;</tr>
                                <tr>&nbsp;</tr>  
                                <TR>   
                                    <TD align=center>
                                        <img src="images/logo.png" border=0 height="60" width="280">
                                    </TD>

                                </TR>
                        </TABLE>
                    </td>
                </tr>

                <tr>

                    <td colspan=2 height=150>

                        <TABLE cellSpacing=1 cellPadding=2 width="320" align=center border=0 bordercolor="#FFFFFF" bordercolorlight="#eeeeee" bordercolordark="#ffffff">
                            <TBODY> 
                                <TR>    
                                    <TD>
                                        <TABLE cellSpacing=1 cellPadding=1 width="100%" border=0>
                                            <TBODY>
                                                <TR>
                                                    <TH colSpan=2>User Login</TH></TR>
                                                <TR>
                                                    <TD class=caption width="10%">User ID</TD>
                                                    <TD width="100%"><INPUT onclick=this.select() 
                                                                            value="<%=userid%>" name="userid" id="userid" autocomplete="off" <%=classStyle%> > </TD>
                                                </TR>
                                                <TR>
                                                    <TD class=caption width="10%">Password</TD>
                                                    <TD width="100%"><INPUT onclick=this.select() 
                                                                            type=password value="<%=password%>" name="password" id="password" autocomplete="off" <%=classStyle%> > </TD>
                                                </TR> 
                                            </TBODY></TABLE>

                                        <TABLE cellSpacing=1 cellPadding=1 width="100%" border=0>

                                            <TBODY> 

                                                <%
                                                    if (returnCode != null && returnCode.equals("0")) {
                                                %>
                                                <TR>
                                                    <TD colspan=2 width="90%"></TD>
                                                    <TD width="15%"><INPUT type=button name="btnReset" value=Reset onclick="resetForm('CLEAR');" class=button-login ></TD>
                                                    <TD width="1%"><INPUT name="btnLogin" style="display:none"></TD>
                                                </TR>
                                                <TR>
                                                    &nbsp; 

                                                </TR> 

                                                <TR>
                                                    <TD colspan="5" class="caption" >Choose your authentication method to complete the login.</TD>
                                                </TR>     
                                                <TR align="center">


                                                    <TD><INPUT onclick="authReq('2');" name="btnSMSLogin" type="button" value="" class=imgSMS <%=smsAuth != null ? classStyle : classStyle2%> <%=smsDisplay%> ></TD>
                                                    <TD><INPUT onclick="authReq('3');" name="btnOTPLogin" type="button" value="" class=imgOtp <%=otpAuth != null ? classStyle : classStyle2%> <%=otpDisplay%> ></TD>
                                                    <TD><INPUT onclick="authReq('5');" name="btnOTPLogin" type="button" value="" class=imgCROtp <%=crOtpAuth != null ? classStyle : classStyle2%> <%=crOtpDisplay%> ></TD>
                                                    <TD><INPUT onclick="return pkiLogin();" name="btnPKILogin" type="button" value="" class=imgPKI <%=pkiAuth != null ? classStyle : classStyle2%> <%=pkiDisplay%> ></TD>
                                                    <TD><INPUT onclick="authReq('7');" name="btnQnaLogin" type="button" value="" class=imgQna <%=qnaAuth != null ? classStyle : classStyle2%> <%=qnaDisplay%> ></TD>

                                                </TR>

                                                <%  } else { %>  
                                                <TR>
                                                    <TD colspan="2" width="55%"></TD>
                                                    <TD><INPUT type=button value=Clear name="btnClear" class=button-login onclick="resetForm('CLEAR');" ></TD>
                                                    <TD><INPUT onclick="return login('1');" name="btnLogin" type=submit value="Log In" class=button-login></TD>
                                                </TR>
                                                <%
                                                    }
                                                %>  
                                        </TABLE>
                                        <TABLE> 
                                            <TBODY>

                                                <TR id="input0" class="hide-row">
                                                    <TD colspan=2 class=caption width="40%"><div id="requestCRChallenge">Challenge :</div></TD>
                                                    <TD  width="30%" 
                                                         value="" name="challenge" id="challenge"><%=crOtpChallenge%>
                                                    </TD>
                                                    <!--          <TD width="20%">
                                                                  <INPUT onclick="requestCrChallenge();" name="btnReqChallenge" type=button value="Request Challenge" 
                                                                         class=button-login>
                                                              </TD> -->
                                                </TR>


                                                <TR id="input1" class="hide-row">
                                                    <TD colspan=2 class=caption width="40%"><div id="requestTokenTitleLogin"></div></TD>
                                                    <TD  width="30%">
                                                        <INPUT onclick=this.select() 
                                                               value="" name="otp" id="otp" autocomplete="off">
                                                    </TD>
                                                    <TD width="20%">
                                                        <INPUT onclick="authLogin();" name="btnAuthLogin" type=button value="Submit" 
                                                               class=button-login>
                                                        <input type="hidden" id="LoginAuthMode" value="<%=authMode%>"/>
                                                    </TD>
                                                </TR>


                                            </TBODY>      
                                        </TABLE>   
                                        <%
                                            if (authMode.equals("7")) {
                                        %>
                                        <TABLE id="qnalist" class ="hide-row" cellSpacing=1 cellPadding=1 width="100%" border=0>  
                                            <TBODY>
                                                <TR>
                                                    <TD class=caption width="40%" style="bold">Please fill in the following questions:</TD>
                                                </TR>
                                                <TR>
                                                    &nbsp; 

                                                </TR> 
                                                <% for (LinkedTreeMap<String, String> question : questions) {%>

                                                <TR>
                                            <input type="hidden" id="<%= quesNum + "id"%>" name="<%= quesNum + "id"%>" value="<%= question.get("id")%>"/>
                                            <TD class=caption width="40%"><%= question.get("question")%></TD>
                                </TR>
                                <TR>
                                    <TD>
                                        <INPUT type="password" onclick=this.select() value="" name="<%= quesNum + "ans"%>" id="<%= quesNum + "ans"%>" autocomplete="off">
                                    </TD>
                                </TR>
                                <%
                                        quesNum++;
                                    }
                                %>
                                <TR>
                                    <TD width="60%"/>
                                    <TD width="20%">
                                        <INPUT onclick="authLogin();" name="btnAuthLogin" type=button value="Submit" 
                                               class=button-login>
                                        <input type="hidden" id="LoginAuthMode" value="<%=authMode%>"/>
                                    </TD>
                                </TR>

                            </TBODY>

                        </TABLE>

                        <%
                            }
                        %>

                    </TD></TR>
                </TBODY></TABLE>
            </td>
            <!--<td width=100% height=450></td>-->
            </tr>
        <tr><td colspan=2 height=80 valign=bottom>
                <table cellpadding=0 cellspacing=0 border=0 width="100%">

                    <tr><td class="" width="50%" align=right valign=bottom height=10>

                    <center><font color="##1A75BB"> Reminder :</font>				
                        <font color="##1A75BB"> <b>You should never reveal your User ID and/or Password to anyone.</b></font>
                    </center>

            </td></tr>

        <tr><td class="" width="50%" align=right valign=bottom height=10>



            </td></tr>

    </table>
</td></tr>
</TABLE>
<div id="registerlink" align="center" <%=displayLink%> >
    <font color="##1A75BB"><a href="#" onclick="goToPage('selfregister.jsp');" title="Register New Account">Lấy mã activation code</a></font>
</div>
<div id="error-message" class="alert-box error" align="center">
    <span align="center">error: </span><text id="error-text"></text>
    <a href = "javascript:void(0)" style="text-align:right; display:block;" onclick = "closeAlert();">Close</a>
</div>
<div id="notice-message" class="alert-box notice" align="center"><span align="center">notice: </span><text id="notice-text"></text></div>  
<div id="fade" class="black_overlay"></div>    
<INPUT name="pageid" id="pageid" type="hidden" value="login"> 
<a id="showlink" href = "javascript:void(0)" style="text-align:left; display:block;" onclick = "document.getElementById('showlink').style.display = 'none';
        document.getElementById('logcontent').style.display = 'block';">Show</a>
<div id="logcontent" style="display:none;">
    <a href = "javascript:void(0)" style="text-align:left;" onclick = "document.getElementById('logcontent').style.display = 'none';
            document.getElementById('showlink').style.display = 'block';">Hide</a>    
    <text id="displayconsolelog" name="displayconsolelog"><%=consolelog%></text>
</div>
<INPUT name="consolelog" id="consolelog" type="hidden" value="<%=consolelog%>">
</FORM>	
</BODY>
</HTML>
