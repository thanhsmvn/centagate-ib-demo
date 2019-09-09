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
    String BaseURL = sysProp.getProperty(Config.BASE_URL);//resource.getString("baseurl");
    String authOption = sysProp.getProperty(Config.AUTH_OPTION);//resource.getString("authOption");
    String userid = (String) request.getSession().getAttribute("userid");
    String password = (String) request.getSession().getAttribute("password");
    String loginSession = (String) request.getSession().getAttribute("loginSession");
    String otpChallengeDisplay = (String) request.getSession().getAttribute("otpChallengeDisplay");
    
    String consolelog = (String) request.getSession().getAttribute("consolelog");
    if(consolelog.length()>5000)
    {
        consolelog="";
    }
    //  String otpChallenge = "";
    DateCalculator dateCalculator = new DateCalculator();
    String todayDate = dateCalculator.convertToDate(System.currentTimeMillis(), "yyyy-MM-dd");
    String otpChallenge = (String) request.getSession().getAttribute("otpChallenge");

    userid = (String) request.getSession().getAttribute("userid");
    password = (String) request.getSession().getAttribute("password");

%>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Main Page</title>
        <style type="text/css"><%@ include file="/styles/login.css" %></style>
        <style type="text/css"><%@ include file="/styles/styles.css" %></style>

        <script language="javascript" src="javascript/JSfunction.js"></script>
        <script language="javascript" src="javascript/JSFormat.js"></script>
        <script language="javascript" src="javascript/JSInvoke.js"></script>
        <script language="javascript" src="javascript/jquery-1.11.1.js"></script>
        <script language="javascript" src="javascript/jquery-ui-1.10.4.js"></script>
        <script type="text/javascript" src="javascript/fingerprint2.min.js"></script>
        <script type="text/javascript" src="javascript/centagate-agent.js"></script>
        <script language="javascript">
            
            var WebSafeBase64={

                                _keyStr:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=",

                                encode:function(e, isPaddingOmitted)
                                {
                                        var t="";
                                        var n,r,i,s,o,u,a;
                                        var f=0;
                                        e=this._utf8_encode(e);

                                        while( f < e.length )
                                        {
                                                n=e.charCodeAt(f++);
                                                r=e.charCodeAt(f++);
                                                i=e.charCodeAt(f++);
                                                s=n>>2;
                                                o=(n&3)<<4|r>>4;
                                                u=(r&15)<<2|i>>6;
                                                a=i&63;
                                                if(isNaN(r))
                                                {
                                                        u=a=64;
                                                }
                                                else if(isNaN(i))
                                                {
                                                        a=64;
                                                }
                                                t=t+this._keyStr.charAt(s)+this._keyStr.charAt(o)+this._keyStr.charAt(u)+this._keyStr.charAt(a);
                                        }
                                        
                                        if(isPaddingOmitted === true)
                                        {
                                            t = t.replace(/=/g,"");
                                        }
                                        return t;
                                },

                                decode:function(e)
                                {
                                        var t="";
                                        var n,r,i;
                                        var s,o,u,a;
                                        var f=0;
                                        e=e.replace(/[^A-Za-z0-9\-\_=]/g,"");
                                        
                                        if(e.length %4 != 0 )
                                        {
                                            e = e + "====".substring(0 , (e.length %4 ));
                                        }
                                        
                                        while(f<e.length)
                                        {
                                                s=this._keyStr.indexOf(e.charAt(f++));
                                                o=this._keyStr.indexOf(e.charAt(f++));
                                                u=this._keyStr.indexOf(e.charAt(f++));
                                                a=this._keyStr.indexOf(e.charAt(f++));
                                                n=s<<2|o>>4;r=(o&15)<<4|u>>2;i=(u&3)<<6|a;
                                                t=t+String.fromCharCode(n);
                                                if(u!=64)
                                                {
                                                        t=t+String.fromCharCode(r);
                                                }
                                                if(a!=64)
                                                {
                                                        t=t+String.fromCharCode(i);
                                                }
                                        }

                                        t=this._utf8_decode(t);
                                        return t;
                                },

                                _utf8_encode:function(e)
                                {
                                        e=e.replace(/rn/g,"n");
                                        var t="";
                                        for(var n=0;n<e.length;n++)
                                        {
                                                var r=e.charCodeAt(n);
                                                if(r<128)
                                                {
                                                        t+=String.fromCharCode(r);
                                                }
                                                else if(r>127&&r<2048)
                                                {
                                                        t+=String.fromCharCode(r>>6|192);
                                                        t+=String.fromCharCode(r&63|128);
                                                }
                                                else
                                                {
                                                        t+=String.fromCharCode(r>>12|224);
                                                        t+=String.fromCharCode(r>>6&63|128);
                                                        t+=String.fromCharCode(r&63|128);
                                                }
                                        }
                                        return t;
                                },

                                _utf8_decode:function(e)
                                {
                                        var t="";
                                        var n=0;
                                        var r=c1=c2=0;
                                        while(n<e.length)
                                        {
                                                r=e.charCodeAt(n);
                                                if(r<128)
                                                {
                                                        t+=String.fromCharCode(r);
                                                        n++
                                                }
                                                else if(r>191&&r<224)
                                                {
                                                        c2=e.charCodeAt(n+1);
                                                        t+=String.fromCharCode((r&31)<<6|c2&63);
                                                        n+=2;
                                                }
                                                else
                                                {
                                                        c2=e.charCodeAt(n+1);
                                                        c3=e.charCodeAt(n+2);
                                                        t+=String.fromCharCode((r&15)<<12|(c2&63)<<6|c3&63);
                                                        n+=3;
                                                }
                                        }
                                        return t;
                                }
                        };    

            var baseURL = getBaseURL();
            d = new Date();
            function setWINDOW()
            {
                if ('<%=loginSession%>' !== '1') {
                    document.getElementById('fade').style.display = 'block';
                    document.getElementById('notice-message').style.display = 'block';
                    document.getElementById('notice-text').innerHTML = "Require to login";
                    setTimeout(function () {
                        window.location = (baseURL + "/login.jsp");
                    }, 2000);
                }
            }


            function cancel()
            {

                window.document.FORM.btnproceed.style.visibility = 'visible';
//        if ('<%=authOption%>'==='Y') {
//            document.getElementById('otpChallenge').style.display='none';
//        }
//        else {
//            document.getElementById('otpChallenge').style.display='none';
//            document.getElementById('qrCodeDisplay').style.display='none';
//            document.getElementById('qr_click_row').style.display='none';
//        }
                document.getElementById('tac').style.display = 'none';
                document.getElementById('transOption').style.display = 'none';
                document.getElementById('input1').style.display = 'none';
                document.getElementById('input0').style.display = 'none';
                document.getElementById('success-message-noclose').style.display = 'none';
                window.document.FORM.amount.className = "mandatory";
                window.document.FORM.amount.readOnly = false;
                window.document.FORM.amount.tabIndex = "-1";
                window.document.FORM.amount.value = "";

                window.document.FORM.toaccount.className = "mandatory";
                window.document.FORM.toaccount.readOnly = false;
                window.document.FORM.toaccount.tabIndex = "";
                window.document.FORM.toaccount.value = "";

                window.document.FORM.effdate.className = "mandatory";
                window.document.FORM.effdate.readOnly = false;
                window.document.FORM.effdate.tabIndex = "";
                window.document.FORM.effdate.value = "";

                window.document.FORM.recemail.className = "";
                window.document.FORM.recemail.readOnly = false;
                window.document.FORM.recemail.tabIndex = "";
                window.document.FORM.recemail.value = "";

                window.document.FORM.desc.className = "";
                window.document.FORM.desc.readOnly = false;
                window.document.FORM.desc.tabIndex = "";
                window.document.FORM.desc.value = "";

                window.document.FORM.tac.className = "";
                if ('<%=authOption%>' === 'Y') {
                    window.document.FORM.btnOTPLogin.disabled = false;
                    window.document.FORM.btnSMSLogin.disabled = false;
                }
                log = document.getElementById('consolelog').value;
                log = log + "<br>" + d.toLocaleString() + " : " + "Status validation stopped";
                document.getElementById('consolelog').value = log;
                document.getElementById('displayconsolelog').innerHTML = log;
                clearInterval(loginStateCheckService);
            }

            function proceed()
            {
                window.document.FORM.btnQRLogin.style.visibility = 'visible';
                window.document.FORM.btnPushCr.style.visibility = 'visible';
                if (CheckMandatory(window.document.FORM))
                {
                    window.document.FORM.amount.className = "input-display";
                    window.document.FORM.amount.readOnly = true;
                    window.document.FORM.amount.tabIndex = "-1";

                    window.document.FORM.toaccount.className = "input-display";
                    window.document.FORM.toaccount.readOnly = true;
                    window.document.FORM.toaccount.tabIndex = "-1";

                    window.document.FORM.effdate.className = "input-display";
                    window.document.FORM.effdate.readOnly = true;
                    window.document.FORM.effdate.tabIndex = "-1";

                    window.document.FORM.recemail.className = "input-display";
                    window.document.FORM.recemail.readOnly = true;
                    window.document.FORM.recemail.tabIndex = "-1";

                    window.document.FORM.desc.className = "input-display";
                    window.document.FORM.desc.readOnly = true;
                    window.document.FORM.desc.tabIndex = "-1";

                    window.document.FORM.btnproceed.style.visibility = 'hidden';
                    //window.document.FORM.btnclear.style.visibility = 'hidden';  
                    document.getElementById('transOption').style.display = 'block';
                    displayButtons();
                } else {
                    window.location.replace(getBaseURL() + "/main.jsp");
                }
            }

            /*  
             * Update 23/03/2017
             * State Bank of Viet Nam
             * ===========================    
             * Type A: <=20M VND  --> SMS
             * Type B: <100M VND  --> OTP, CR OTP
             * Type C: <500M VND  --> Push CR, QR Code
             * Type D: >=500M VND --> PKI
             */
            function displayButtons() {
                amt = eval(window.document.FORM.amount.value);
                if (amt <= 20) { //type A
                    //display all
                } else if (amt < 100) { //type B                       
                    window.document.FORM.btnSMSLogin.style.visibility = 'hidden';
                } else if (amt < 500) { //type C
                    window.document.FORM.btnSMSLogin.style.visibility = 'hidden';
                    window.document.FORM.btnOTPLogin.style.visibility = 'hidden';
                    window.document.FORM.btnCrOTPLogin.style.visibility = 'hidden';
                } else { //type D
                    window.document.FORM.btnSMSLogin.style.visibility = 'hidden';
                    window.document.FORM.btnOTPLogin.style.visibility = 'hidden';
                    window.document.FORM.btnCrOTPLogin.style.visibility = 'hidden';
                    window.document.FORM.btnPushCr.style.visibility = 'hidden';
                    window.document.FORM.btnQRLogin.style.visibility = 'hidden';
                }
            }

            function verifyTrans(req) {
                document.getElementById('transOption').style.display = 'none';
                window.document.FORM.btnclear.style.visibility = 'hidden';
                window.document.FORM.btnQRLogin.style.visibility = 'hidden';
                window.document.FORM.btnPushCr.style.visibility = 'hidden';

                if (req === '2' || req === '3' || req === '4' || req === '5'||req === '9') {
                    document.getElementById('tac').style.display = 'block';
                    transReq(req);
                } else if (req === '6' || req === '8') {
                    console.log("PKIIIIIIIIIII");
                    transReq(req);
                } else {
                    return;
                }

            }

            function transReq(req)
            {
                if (CheckMandatory(window.document.FORM))
                {
                    console.log("GET INVOKE" + req);
                    if ('<%=authOption%>' === 'Y') {
                        window.document.FORM.btnOTPLogin.disabled = true;
                        window.document.FORM.btnSMSLogin.disabled = true;

                        document.getElementById('input1').style.display = 'table-row';
                        window.document.FORM.tac.className = "mandatory";
                    }
                    //window.document.FORM.action = baseURL+"/LoginServlet?REQ="+req;
                    //window.document.FORM.submit();
                    amt = window.document.FORM.amount.value;
                    fromacct = window.document.FORM.fromaccount.value;
                    toacc = window.document.FORM.toaccount.value;
                    effdate = window.document.FORM.effdate.value;
                    recmail = window.document.FORM.recemail.value;
                    desc = window.document.FORM.desc.value+
                            window.document.FORM.fromaccount.value+
                            window.document.FORM.effdate.value+
                            window.document.FORM.toaccount.value;
                    
                    console.log("GET INVOKE1" + req);
                    
                    getInvoke(req, "<%=userid%>", amt, fromacct, toacc, effdate, recmail, desc);
                } else
                {
                    return;
                }
            }




            function TACSubmit(mode)
            {
                if (CheckMandatory(window.document.FORM))
                {
                    window.document.FORM.btnAuthLogin.disabled = true;
                    window.document.FORM.tac.className = "input-display";
                    //window.document.FORM.action = baseURL+"/TransServlet?MODE="+mode;
                    //window.document.FORM.submit();	 
                    getInvokeTAC(
                            window.document.FORM.reqCode.value, "<%=userid%>",
                            window.document.FORM.tac.value, window.document.FORM.challenge.value);
                } else
                {
                    return;
                }
            }

            function logout()
            {
                document.getElementById('fade').style.display = 'block';
                document.getElementById('notice-message').style.display = 'block';
                document.getElementById('notice-text').innerHTML = "Logout Succesful";

                window.document.FORM.action = baseURL + "/LoginServlet?MODE=LOGOUT";
                window.document.FORM.submit();
            }

            function showQrOtpInput() {
                document.getElementById('input1').style.display = 'table-row';
                document.getElementById('input0').style.display = 'table-row';
                //         document.getElementById('otpChallengeDisplay').innerHTML ="<%=otpChallenge%>"; 
                window.document.FORM.tac.className = "mandatory";
                clearInterval(loginStateCheckService);
                return;
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
                                <td class=login-body width="40%" align=center colspan="3">Enterprise Solution for Global Banking</td>
                            </tr>
                            <tr>
                                <td class=login-body width="40%" align=left colspan="2"></td>
                                <td class=login-caption width="40%" align=right>
                                    <INPUT onclick="logout();" name="btnLogout" type=submit value="Logout" class=imgLogout >
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
            <fieldset width="70%" class="fieldsettitle">
                <br>
                <TABLE BORDER="0" WIDTH="70%" CELLSPACING="0" CELLPADDING="3" ALIGN="CENTER">
                    <TR>
                        <TH colSpan=5>New Account Transfer</TH>
                    </TR>    
                    <TR>
                        <TD class="caption" width="20%">Amount</TD>
                        <TD width="30%"><input type="text" name="amount" id="amount" value="10" class="mandatory"></TD>
                        <TD colspan=3 > (millions VND)</TD>  
                    </TR>
                    <TR>
                        <TD class="caption" width="20%">From Account</TD>
                        <TD width="30%"><input type="text" name="fromaccount" id="fromaccount" value="11402236836 SA" readonly tabindex="-1" class="input-display"></TD>
                        <TD width="5%"></TD>
                        <TD class="caption" width="20%">To Account</TD>
                        <TD width="30%"><input type="text" name="toaccount" id="toaccount" value="55204436106" class="mandatory"></TD> 
                    </TR>

                    <TR>
                        <TD class="caption" width="20%">Effective Date</TD>
                        <TD width="30%"><input type="text" name="effdate" id="effdate" value="<%=todayDate%>" class="mandatory" onChange="formatDate(this.value);" placeholder="yyyy-mm-dd"></TD>
                        <TD width="5%"></TD>
                        <TD class="caption" width="20%"></TD>
                        <TD width="30%"><input type="hidden" name="recemail" id="recemail" value="" ></TD> 
                    </TR>

                    <TR rowspan="2">
                        <td colspan="5">&nbsp;</td> 
                    </TR> 
                    <input type="hidden" name="desc" id="desc" value="">    
                </TABLE>

                <TABLE BORDER="0" WIDTH="70%" CELLSPACING="0" CELLPADDING="3" ALIGN="CENTER">
                    <TR>
                        <TD width="35%"></TD>
                        <TD width="15%"><INPUT onclick="cancel();" name="btnclear" type=button value="Clear" class=button-login></TD>
                        <TD width="15%"><INPUT onclick="proceed();" name="btnproceed" type=button value="Proceed" class=button-login></TD>
                        <TD width="35%"></TD>
                    </TR>
                </TABLE>            

                <div id="transOption" class="hide-row">
                    <br></br><br/>
                    <TABLE BORDER="0" WIDTH="70%" CELLSPACING="0" CELLPADDING="3" ALIGN="CENTER">
                        <TR>
                            <TH colspan=6>Transaction Authorization</TH>
                        </TR>  
                        <TR>
                            <TD colspan=6 class="caption">Please select a method below to verify and complete the transaction.</TD>
                        </TR>
                        <TR>          
                            <TD><INPUT onclick="verifyTrans('2');" name="btnSMSLogin" type="button" value="SMS" class=button-login ></TD>
                            <TD><INPUT onclick="verifyTrans('3');" name="btnOTPLogin" type="button" value="OTP" class=button-login ></TD>                                                                                             
                            <TD><INPUT onclick="verifyTrans('5');" name="btnCrOTPLogin" type="button" value="CR OTP" class=button-login ></TD>
                            <TD><INPUT onclick="verifyTrans('8');" name="btnPushCr" type=button value="Mobile Push" class=button-login ></TD> 
                            <TD><INPUT onclick="verifyTrans('4');" name="btnQRLogin" type=button value="QR Code" class=button-login></TD>
                            <TD><INPUT onclick="verifyTrans('6');" name="btnPKILogin" type="button" value="PKI" class=button-login ></TD>  
                            <TD><INPUT onclick="verifyTrans('9');" name="btnSignLogin" type="button" value="Signing OTP" class=button-login ></TD>
                        </TR>
                    </TABLE>
                    <br/><br/><br/><br/>
                </div>

                <div id="tac" class="hide-row">

                    <TABLE BORDER="0" WIDTH="70%" CELLSPACING="0" CELLPADDING="3" ALIGN="CENTER">
                        <TR>
                            <TH colSpan=5>Transaction Authorization</TH>
                        </TR>  
                        <% if (authOption != null && authOption.equals("Y")) {%>      
                        <TR>
                            <TD colspan=5 class="caption" width="20%">Choose method below to request the TAC number to complete the transaction.</TD>
                        </TR>
                        <TR>
                        <TR align="center">
                            <TD width="35%"></TD>
                            <TD width="15%"><INPUT onclick="transReq('2');" name="btnSMSLogin" type=submit value="" class=imgSMS></TD>
                            <TD width="15%"><INPUT onclick="transReq('3');" name="btnOTPLogin" type=submit value="" class=imgCROtp ></TD>
                            <TD width="15%"><INPUT onclick="transReq('4');" name="btnQRLogin" type=submit value="" class=imgQRCode ></TD>
                            <TD width="35%"></TD>
                        </TR>
                        <% } %>
                    </TABLE>  

                    <TABLE BORDER="0" WIDTH="70%" CELLSPACING="0" CELLPADDING="3" ALIGN="CENTER"> 

                        <% if (authOption != null && authOption.equals("Y")) {%>     
                        <TR id="otpChallenge" class="hide-row">
                            <TD colspan=2 class=caption width="50%">Challenge Code</TD>
                            <TD  colspan=2 width="50%">
                                <INPUT
                                    value="<%=otpChallenge%>" name="challenge" id="challenge" autocomplete="off" readonly tabindex=-1 class=input-display>
                            </TD>
                            <TD width="50%">&nbsp;</TD>
                        </TR>
                        <% } else {%>
                        <!--TAC for QR Authentication -->
                        <INPUT value="<%=otpChallenge%>" name="challenge" id="challenge" type="hidden">
                        <TR id="otpChallenge" class="hide-row">
                            <TD colspan=5 class=caption width="50%">Please scan this QR Code</TD>
                        </TR>
                        <TR id="qrCodeDisplay" class="hide-row">
                            <TD  colspan=5 align=center>
                                <img id="qrCode" WIDTH=350 HEIGHT=350 src="" />
                            </TD>
                        </TR>  

                        <% }%>

                        <!--TAC for SMS, OTP, CROTP Authentication -->
                        <TR id="tac_click_row" class="hide-row">
                            <td colspan="5" alig="center">
                                <a href="#" onclick="return showTACInput();">Click here to enter the TAC manually</a>
                            </td>
                        </TR>
                        <TR id="tac_info_row" class="hide-row">
                            <TD colspan=5 class="caption" width="20%">Please enter the TAC to complete the transaction.</TD>
                        </TR>
                        <TR id="input0" class="hide-row">
                            <TD width="30%"> </TD>    
                            <TD class=caption width="15%"><text id="challengeDisplay"></text></TD>                      
                            <TD colspan=3><text id="otpChallengeDisplay"></text></TD>
                        </TR> 
                        <TR id="input1" class="hide-row">
                            <TD width="30%"> </TD>    
                            <TD class=caption width="15%"><text id="tacDisplay"></text></TD>
                            <TD  width="15%">
                                <INPUT onclick=this.select() value="" name="tac" id="tac" autocomplete="off" >
                            </TD>
                            <TD width="15%">
                                <INPUT onclick="TACSubmit();" name="btnAuthLogin" type=button value="Submit" class=button-login>
                            </TD>
                            <TD width="30%"></TD>   
                        </TR>    
<!--                        <TR id="input0" class="hide-row">
                            <TD width="30%"> </TD>    
                            <TD class=caption width="15%"><text id="challengeDisplay"></text></TD>                      
                            <TD colspan=3><text id="otpChallengeDisplay"></text></TD>
                        </TR>-->
                    </TABLE>   

                </div> 

            </fieldset>
        </center>
        <div id="error-message" class="alert-box error" align="center">
            <span align="center">error: </span><text id="error-text"></text>
            <a href = "javascript:void(0)" style="text-align:right; display:block;" onclick = "backtomain();">Close</a>
        </div>  
        <div id="success-message-noclose" class="alert-box success-noclose" align="center">
            <span align="center">success: </span><text id="success-text-noclose"></text>
            <br>
            <img src="images/spinner-small.gif" border=0 height="50" width="50" align="center">
        </div>                  
        <div id="success-message" class="alert-box success" align="center">
            <span align="center">success: </span><text id="success-text"></text>
            <a href = "javascript:void(0)" style="text-align:right; display:block;" onclick = "backtomain();">Close</a>
        </div>  
        <div id="notice-message" class="alert-box notice" align="center"><span align="center">notice: </span><text id="notice-text"></text></div>  
        <div id="fade" class="black_overlay"></div>   
        <INPUT value="<%=userid%>" name="userid" id="userid" type="hidden" > 
        <INPUT value="<%=password%>" name="password" id="password" type="hidden" > 
        <INPUT name="reqCode" id="reqCode" type="hidden" > 
        <INPUT name="pageid" id="pageid" type="hidden" value="login"> 
        <a id="showlink" href = "javascript:void(0)" style="text-align:left; display:block;" onclick = "document.getElementById('showlink').style.display = 'none';document.getElementById('logcontent').style.display = 'block';">Show</a>
        <div id="logcontent" style="display:none;">
            <a href = "javascript:void(0)" style="text-align:left;" onclick = "document.getElementById('logcontent').style.display = 'none';
                    document.getElementById('showlink').style.display = 'block';">Hide</a>    
            <text id="displayconsolelog" name="displayconsolelog"><%=consolelog%></text>
        </div>
        <INPUT name="consolelog" id="consolelog" type="hidden" value="<%=consolelog%>">
        </body>
    </form>

</html>
