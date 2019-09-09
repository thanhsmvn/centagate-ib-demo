<%-- 
    Document   : main
    Created on : Jul 15, 2015, 3:27:27 PM
    Author     : auyong
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@ page language = "java" %>
<%@ page session= "true" %>
<%@ page import = "java.util.*" %>
<%@ page import = "com.securemetric.web.util.DateCalculator" %>
<%@ page import = "com.securemetric.web.util.Config"%>
<!DOCTYPE html>

<%
    Config sysConfig = new Config();
    Properties sysProp = sysConfig.getConfig(Config.TYPE_SYSTEM);
//ResourceBundle resource = ResourceBundle.getBundle("system");
    String BaseURL = sysProp.getProperty(Config.API_URL);//resource.getString("apiurl");
    String passwordMinLength = sysProp.getProperty(Config.PASSWORD_MIN);//resource.getString("passwordMinLength");
    String passwordComplexity = sysProp.getProperty(Config.PASSWORD_COMPLEX);//resource.getString("passwordComplexity");

    String consolelog = (String) request.getSession().getAttribute("consolelog");
    if (consolelog == null) {
        consolelog = "";
    }
    DateCalculator dateCalculator = new DateCalculator();
    String todayDate = dateCalculator.convertToDate(System.currentTimeMillis(), "yyyy-MM-dd");
%>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <meta http-equiv="Pragma" content="no-cache" /> 
        <meta http-equiv="Cache-Control" content="private, no-store, no-cache, must-revalidate" /> 

        <title>Main Page</title>
        <style type="text/css"><%@ include file="/styles/login.css" %></style>
        <style type="text/css"><%@ include file="/styles/styles.css" %></style>

        <script language="javascript" src="javascript/JSfunction.js"></script>
        <script language="javascript" src="javascript/JSFormat.js"></script>
        <script language="javascript" src="javascript/JSInvoke.js"></script>
        <script language="javascript" src="javascript/jquery-1.11.1.js"></script>
        <script language="javascript" src="javascript/jquery-ui-1.10.4.js"></script>
        <script type="text/javascript" src="javascript/fingerprint2.min.js"></script>
        <script language="javascript">




            var baseURL = getBaseURL();
            d = new Date();
            var scanStateCheckService;

            function cancel()
            {
                window.document.FORM.username.className = "mandatory";
                window.document.FORM.username.readOnly = false;
                window.document.FORM.username.tabIndex = "";
                window.document.FORM.username.value = "";

                window.document.FORM.password.className = "mandatory";
                window.document.FORM.password.readOnly = false;
                window.document.FORM.password.tabIndex = "";
                window.document.FORM.password.value = "";

                window.document.FORM.cpassword.className = "mandatory";
                window.document.FORM.cpassword.readOnly = false;
                window.document.FORM.cpassword.tabIndex = "";
                window.document.FORM.cpassword.value = "";

                window.document.FORM.cmobile.className = "mandatory";
                window.document.FORM.cmobile.readOnly = false;
                window.document.FORM.cmobile.tabIndex = "";
                window.document.FORM.cmobile.value = "";

                window.document.FORM.mobileno.className = "mandatory";
                window.document.FORM.mobileno.readOnly = false;
                window.document.FORM.mobileno.tabIndex = "";
                window.document.FORM.mobileno.value = "";

                window.document.FORM.actCodeTxt.className = "";
                window.document.FORM.actCodeTxt.value = "";

                window.document.FORM.btnregister.disabled = false;
                window.document.FORM.btnactivate.disabled = false;
                window.document.FORM.btnclear.disabled = false;

                document.getElementById("register").style.color = "blue";
                document.getElementById('register').style.display = 'block';
                document.getElementById('activation').style.display = 'none';
                document.getElementById('device').style.display = 'none';
            }

            var username;
            var mobileno;
            var cmobile;
            var userId;
            var activationCode;
            var tokenId;
            var companyId;
            var userEmail;
            var password;
            var cpassword;

            function register()
            {
                username = window.document.FORM.username.value;
                registerUser(username, "password", "cmobile", "");
            }

            var xhttp = new XMLHttpRequest();
            xhttp.onreadystatechange = function () {
                if (xhttp.readyState === 4 && xhttp.status === 200) {
                    myFunction(xhttp);
                }
            }
            xhttp.open("GET", "./xml/phone.xml", true);
            xhttp.send();

            function myFunction(xml) {
                var xmlDoc = xml.responseXML;
                var x = xmlDoc.getElementsByTagName('iso');
                var y = xmlDoc.getElementsByTagName('itu');
                var str = '<select name=cmobile id=cmobile class=mandatory>';
                for (i = 0; i < x.length; i++) {
                    str += '<option value=' + y[i].childNodes[0].nodeValue + '>' + x[i].childNodes[0].nodeValue + y[i].childNodes[0].nodeValue + '</option>';
                }
                str += '</select>';

                document.getElementById("country").innerHTML = str;
            }


            function registerUser(username, password, cmobile, mobileno) {

                console.log(username + "," + password + "," + cmobile + "," + mobileno);

                setConsoleLog("Sending registration info to server");
                var url = "./registerServlet?mode=1&username=" + username + "&password=" + password + "&cmobile=" + cmobile + "&mobileno=" + mobileno;
                $.ajaxSetup({
                    cache: false
                });

                $.ajax({
                    url: url,
                    type: "POST"
                }).done(function (data) {


                    alert(data);

                }).fail(function (jqXHR, textStatus, errorThrown) {
                    // log the error to the console
                    console.error(
                            "The following error occured: " +
                            textStatus, errorThrown
                            );
                });
            }


            function reqAction(obj) {
                //remove onclick event
                if (obj.id == "register") {
                    //do nothing
                } else {
                    obj.onclick = "";
                    obj.style.color = "#bbbbbb";
                }
                smsRequestCode();
            }

            function smsRequestCode() {
                setConsoleLog("Requesting SMS activation code");
                var url = "./registerServlet?mode=2&tokenId=" + tokenId + "&idUserActivationCode=" + activationCode + "&userId=" + userId + "&userCompanyId=" + companyId + "&userEmail=" + userEmail;
                $.ajaxSetup({
                    cache: false
                });

                $.ajax({
                    url: url,
                    type: "POST"
                }).done(function (data) {

                    jsonvalue = JSON.parse(data);
                    codeValue = jsonvalue.code;

                    if (codeValue == "0") {
                        //success
                        msgbox('2', 'User SMS activation code have been send to your mobile');
                        setConsoleLog("User SMS activation code request succesfully");
                    } else {
                        //failed
                        document.getElementById("register").onclick = function ( )
                        {
                            reqAction(document.getElementById("register"));
                        };
                        document.getElementById("register").style.color = "blue";

                        msgbox('1', 'User SMS activation code request failed');
                        setConsoleLog("User SMS activation code request failed");
                    }

                    $('#actCodeTxt').focus();
                }).fail(function (jqXHR, textStatus, errorThrown) {
                    // log the error to the console
                    console.error(
                            "The following error occured: " +
                            textStatus, errorThrown
                            );
                });
            }

            function activate() {
                var regexAct = /^[0-9]{6,8}$/;
                var actCode = trim($('#actCodeTxt').val());

                if (CheckMandatory(window.document.FORM))
                {

                    if (!(regexAct.test(actCode))) {
                        $('#actCodeTxt').focus();
                        msgbox('1', 'Invalid SMS code');
                        window.document.FORM.btnactivate.disabled = false;
                    } else {
                        window.document.FORM.btnactivate.disabled = true;

                        activateUser(actCode);
                    }
                }
            }

            function activateUser(actCode) {
                setConsoleLog("Sending user activation info");
                var url = "./registerServlet?mode=3&tokenId=" + tokenId
                        + "&idUserActivationCode=" + activationCode + "&userId=" + userId
                        + "&userCompanyId=" + companyId + "&userEmail=" + userEmail + "&smsActiveCode=" + actCode
                        + "&password=" + password;

                $.ajaxSetup({
                    cache: false
                });

                $.ajax({
                    url: url,
                    type: "POST"
                }).done(function (data) {
                    jsonvalue = JSON.parse(data);
                    codeValue = jsonvalue.code;

                    if (codeValue == "0") {
                        //success
                        msgbox('2', 'User have activate succesfully');

                        document.getElementById('activation').style.display = 'none';
                        document.getElementById('device').style.display = 'block';

                        window.document.FORM.deviceUsername.value = username;
                        window.document.FORM.deviceMobileNo.value = cmobile + mobileno;
                        setConsoleLog("User have activate succesfully");
                    } else {
                        //failed
                        msgbox('1', 'User activation failed');
                        setConsoleLog("User have activation failed");

                        window.document.FORM.btnactivate.disabled = false;
                    }
                }).fail(function (jqXHR, textStatus, errorThrown) {
                    // log the error to the console
                    console.error(
                            "The following error occured: " +
                            textStatus, errorThrown
                            );
                });
            }


            function registerDevice() {
                document.getElementById('qrDiv').style.display = 'block';
                document.getElementById('oneTimePinInfo').style.display = 'none';
                setConsoleLog("Sending request to register mobile device");
                var url = "./registerServlet?mode=4&userId=" + userId + "&userEmail=" + userEmail;
                $.ajaxSetup({
                    cache: false
                });

                $.ajax({
                    url: url,
                    type: "POST"
                }).done(function (data) {

                    jsonvalue = JSON.parse(data);
                    codeValue = jsonvalue.code;

                    if (codeValue == "0") {
                        //display the QR code

                        if (data.object != "") {
                            document.getElementById("qrDiv").innerHTML = "<img src=\"./qrcode?qrtext=" + encodeURIComponent(jsonvalue.object) + "\" /> <br/> Scan the following QR code using your mobile device";
                            setConsoleLog("Request to register mobile device successful");
                            scanStateCheckService = setInterval(function () {
                                refreshQRState();
                            }, interval);

                        } else {
                            document.getElementById("qrDiv").innerHTML = "Unable generate QR Code. Please try again.";
                            setConsoleLog("Request to register mobile device failed");
                        }
                    } else {

                        msgbox('1', 'Generate QR code request failed');
                    }
                }).fail(function (jqXHR, textStatus, errorThrown) {
                    // log the error to the console
                    console.error(
                            "The following error occured: " +
                            textStatus, errorThrown
                            );
                });
            }

            function reqOneTimePin() {
                document.getElementById('qrDiv').style.display = 'none';
                document.getElementById('oneTimePinInfo').style.display = 'block';
                setConsoleLog("Sending request to register mobile device");
                var url = "./registerServlet?mode=6&username=" + username;
                $.ajaxSetup({
                    cache: false
                });

                $.ajax({
                    url: url,
                    type: "POST"
                }).done(function (data) {

                    jsonvalue = JSON.parse(data);
                    codeValue = jsonvalue.code;

                    if (codeValue == "0") {
                        //display the QR code
                        objectValue = JSON.parse(jsonvalue.object);

                        if (data.object != "") {
                            document.getElementById("passcode").innerHTML = objectValue.passcode;
                            document.getElementById("usernameDisplay").innerHTML = username;
                            setConsoleLog("Request Pin to register mobile device successful");
                            scanStateCheckService = setInterval(function () {
                                refreshQRState();
                            }, interval);

                        } else {
                            document.getElementById("passcode").innerHTML = "Unable to generate One Time Pin. Please try again.";
                            setConsoleLog("Request to register mobile device failed");
                        }
                    } else {

                        msgbox('1', 'Generate one time pin request failed');
                        setConsoleLog("Request to register mobile device failed");
                    }
                }).fail(function (jqXHR, textStatus, errorThrown) {
                    // log the error to the console
                    console.error(
                            "The following error occured: " +
                            textStatus, errorThrown
                            );
                });
            }

            function refreshQRState() {
                setConsoleLog("Verifying user device status ..");
                var url = "./registerServlet?mode=5" + "&userId=" + userId;
                $.ajaxSetup({
                    cache: false
                });

                $.ajax({
                    url: url,
                    type: "POST",
                    timeout: 5000
                }).done(function (data) {
                    jsonvalue = JSON.parse(data);
                    codeValue = jsonvalue.code;

                    if (codeValue == "0") {

                        if (jsonvalue.object != "") {
                            clearInterval(scanStateCheckService);
                            msgbox('2', 'User mobile device register succesfully');
                            setConsoleLog("User scanning QR Code sucessfully");
                            setTimeout(function () {
                                logout();
                            }, 3000);
                        }

                    }
                }).fail(function (jqXHR, textStatus, errorThrown) {
                    // log the error to the console
                    console.error(
                            "The following error occured: " +
                            textStatus, errorThrown
                            );
                    clearInterval(scanStateCheckService);
                });
            }

            function logout()
            {
                window.document.FORM.action = baseURL + "/LoginServlet?MODE=LOGOUT";
                window.document.FORM.submit();
            }

            function setWINDOW()
            {
                setConsoleLog("User registration process start");
            }


            function setConsoleLog(message) {
                log = document.getElementById('consolelog').value;
                log = log + "<br>" + d.toLocaleString() + " : " + message;
                document.getElementById('consolelog').value = log;
                document.getElementById('displayconsolelog').innerHTML = log;
            }
        </script>
    </head>
    <form name="FORM" id="FORM" method="post" action="">
        <input type="hidden" id="browserfp" name="browserfp" value="" />
        <body onload="setWINDOW();" style="background-position: center center; background-repeat: no-repeat">
            <script type="text/javascript">
                new Fingerprint2().get(function (result, components) {
                    $("#browserfp").val(result);
                });
            </script>
            <table cellpadding=0 cellspacing=0 border=0 width="100%">
                <tr><td colspan=2>
                        <table cellpadding=0 cellspacing=0 border=0 width="100%">

                            <tr>
                                <td class=login-body width="40%" align=left colspan="2">Enterprise Solution for Global Banking</td>
                                <td class=login-caption width="40%" align=right>
                                    <INPUT onclick="logout();" name="btnLogout" type=submit value="Home" class=imgLogout >
                                </td>
                            </tr>
                        </table>

                        <TABLE cellSpacing=0 cellPadding=1 width="100" align=center border=0 bordercolor="#FFFFFF" bordercolorlight="#eeeeee" bordercolordark="#ffffff">

                            <TR>   
                                <TD align=center>
                                    <img src="images/logo.png" border=0 height="55" width="220">
                                </TD>

                            </TR>
                        </TABLE>

                    </td></tr>
            </table>    
            <!-- add -->
        <center>
            <fieldset width="50%" class="fieldsettitle">
                <br></br>

                <div id="register">
                    <TABLE BORDER="0" WIDTH="70%" CELLSPACING="10" CELLPADDING="3" ALIGN="CENTER">
                        <TR>
                            <TH colSpan=3>Nhập user name để lấy mã activation</TH>
                        </TR>    
                        <TR>
                            <TD class="caption" width="20%">Username</TD>
                            <TD width="30%" colspan="2"><input type="text" name="username" id="username" value="" class="mandatory"></TD>

                        </TR>

                    </TABLE>

                    <TABLE BORDER="0" WIDTH="70%" CELLSPACING="10" CELLPADDING="3" ALIGN="CENTER">
                        <TR>
                            <TD colspan=2 width="70%"></TD>
                            <TD width="15%"><INPUT onclick="cancel();" name="btnclear" type=button value="Clear" class=button-login></TD>
                            <TD width="15%"><INPUT onclick="register();" name="btnregister" type=button value="Get Activation code" class=button-login></TD>
                        </TR>
                    </TABLE>

                </div> 

                <div id="activation" class="hide-row">

                    <TABLE BORDER="0" WIDTH="70%" CELLSPACING="10" CELLPADDING="3" ALIGN="CENTER" style="margin-left: 16.5%;">
                        <TR>
                            <TH colSpan=3>New user activation</TH>
                        </TR>    
                        <TR>
                            <TD class="caption" width="20%">Username</TD>
                            <TD width="60%" colspan="2"><input type="text" id="actUsername" value="" readonly tabindex="-1" class="input-display"></TD>

                        </TR>
                        <TR>
                            <TD class="caption" width="20%">Mobile No.</TD>
                            <TD width="60%"><input type="text" id="actMobileNo" value="" readonly tabindex="-1" class="input-display"></TD>
                        </TR>

                        <TR>
                            <TD  colspan="3">You can activate your account by entering the SMS code.</TD> 
                        </TR>

                        <TR>
                            <TD colspan="3">
                                <input id="actCodeTxt" name="actCodeTxt" autocomplete="off" type="text" style="width: 100px"  value = ""> 
                                <br>
                                <a href="javascript:void(0);" id="register" style="padding-left: 0px;color: blue;" onclick="reqAction(this);"  >Request SMS code</a>
                            </TD>
                        </TR>
                    </TABLE>

                    <TABLE BORDER="0" WIDTH="70%" CELLSPACING="10" CELLPADDING="3" ALIGN="CENTER">
                        <TR>
                            <TD colspan=2 width="70%"></TD>
                            <TD width="15%"></TD>
                            <TD width="15%"><INPUT onclick="activate();" name="btnactivate" type=button value="Activate" class=button-login></TD>
                        </TR>
                    </TABLE>

                </div>

                <div id="device" class="hide-row">

                    <TABLE BORDER="0" WIDTH="70%" CELLSPACING="10" CELLPADDING="3" ALIGN="CENTER" style="margin-left: 16.5%;">
                        <TR>
                            <TH colSpan=3>Register user mobile device</TH>
                        </TR>    
                        <TR>
                            <TD class="caption" width="20%">Username</TD>
                            <TD width="60%" colspan="2"><input type="text" id="deviceUsername" value="" readonly tabindex="-1" class="input-display"></TD>

                        </TR>
                        <TR>
                            <TD class="caption" width="20%">Mobile No.</TD>
                            <TD width="60%"><input type="text" id="deviceMobileNo" value="" readonly tabindex="-1" class="input-display"></TD>
                        </TR>

                        <TR>
                            <TD colspan="3">Please choose one option to bind your mobile :</TD>

                        </TR>

                        <TR>
                            <TD colspan="3">
                                <a href="javascript:void(0);" onclick="registerDevice();"  class="hyperlink" >Request SMS to bind mobile device with QR Code</a>
                            </TD>
                        </TR>
                        <TR>
                            <TD colspan="3">
                                <a href="javascript:void(0);" onclick="reqOneTimePin();"  class="hyperlink" >Request SMS to bind mobile device with User ID</a>
                            </TD>
                        </TR>
                        <TR>
                            <TD colspan="3" align=center>
                                <div id="qrDiv"></div>
                                <div id="oneTimePinInfo" class="hide-row">
                                    <TABLE BORDER="0" WIDTH="70%" CELLSPACING="0" CELLPADDING="3" ALIGN="CENTER">
                                        <TR>
                                            <TD colspan=5 class="caption" width="20%">Please input the following details to bind your device :</TD>
                                        </TR>
                                        <TR>
                                            <TD colspan=5 class="caption" width="20%">Client ID : <text id="usernameDisplay"></text></TD>


                                        </TR>
                                        <TR>
                                            <TD colspan=5 class="caption" width="80%">Passcode  : <text id="passcode"></text></TD>
                                        </TR>

                                    </TABLE>
                                </div>
                            </TD>
                        </TR>

                    </TABLE>

                    <TABLE BORDER="0" WIDTH="70%" CELLSPACING="10" CELLPADDING="3" ALIGN="CENTER">
                        <TR>
                            <TD colspan=2 width="70%"></TD>
                            <TD width="15%"><INPUT onclick="cancel();" name="btnclear" type=button value="Cancel" class=button-login></TD>
                            <TD width="15%"></TD>
                        </TR>
                    </TABLE>

                </div> 

                <br></br>  
            </fieldset>
        </center>
        <div id="error-message" class="alert-box error" align="center">
            <span align="center">error: </span><text id="error-text"></text>
            <!--    <a href = "javascript:void(0)" style="text-align:right; display:block;" onclick = "backtomain();">Close</a>-->
        </div>  
        <div id="success-message-noclose" class="alert-box success-noclose" align="center">
            <span align="center">success: </span><text id="success-text-noclose"></text>
        </div>                  
        <div id="success-message" class="alert-box success" align="center">
            <span align="center">success: </span><text id="success-text"></text>
            <!--   <a href = "javascript:void(0)" style="text-align:right; display:block;" onclick = "backtoregister();">Close</a>-->
        </div>  
        <div id="notice-message" class="alert-box notice" align="center"><span align="center">notice: </span><text id="notice-text"></text></div>  
        <div id="fade" class="black_overlay"></div>   
        <a id="showlink" href = "javascript:void(0)" style="text-align:left; display:block;" onclick = "document.getElementById('showlink').style.display = 'none';document.getElementById('logcontent').style.display = 'block';">Show</a>
        <div id="logcontent" style="display:none;">
            <a href = "javascript:void(0)" style="text-align:left;" onclick = "document.getElementById('logcontent').style.display = 'none';document.getElementById('showlink').style.display = 'block';">Hide</a>    
            <text id="displayconsolelog" name="displayconsolelog"><%=consolelog%></text>
        </div>
        <INPUT name="consolelog" id="consolelog" type="hidden" value="<%=consolelog%>">
        </body>
    </form>

</html>
