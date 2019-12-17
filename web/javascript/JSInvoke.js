
var interval = "10000";
var loginStateCheckService;
var xmlhttp = new getXMLObject();	//xmlhttp holds the ajax object  
//--Function to get the xmlhttp object
function getXMLObject()  //XML OBJECT
{
    var xmlhttp;
    if (window.XMLHttpRequest)
    {// code for IE7+, Firefox, Chrome, Opera, Safari
        xmlhttp = new XMLHttpRequest();
    } else
    {// code for IE6, IE5
        xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
    }

    return xmlhttp;  // Mandatory Statement returning the ajax object created
}

function getInvoke(req, username, amt, fromacct, toacc, effdate, recmail, desc) {
    var consoleSize=document.getElementById('consolelog').value;
    //alert(consoleSize.length+" =====  "+document.getElementById('consolelog').value);
    if(consoleSize.length>5000)
    {
        document.getElementById('consolelog').value="";
    }
    var url = getBaseURL() + "/TransServlet?REQ=" + req + "&userid=" + username + "&consolelog=" + document.getElementById('consolelog').value
            + "&amt=" + amt + "&fromacct=" + fromacct + "&toacc=" + toacc + "&effdate=" + effdate + "&recmail=" + recmail + "&desc=" + desc;    
    if (req === '6'){
        var dataToSign = username + amt + fromacct + toacc + effdate;

        var plainText = WebSafeBase64.encode(dataToSign, true);
        console.log(plainText);
        p7SignByCsp(false, plainText, 0, onSignCallback, username);
        return;
    }
    if (xmlhttp) {

        document.getElementById('reqCode').value = req;

        xmlhttp.open("GET", url, false);
        //alert(url);
        if (req ==='4') {
            xmlhttp.onreadystatechange = handleServerResponseQR;
        } else if (req === '8'){
            xmlhttp.onreadystatechange = handleServerResponsePushCr;
        } else if (req === '2'){
            xmlhttp.onreadystatechange = handleServerResponseSMS;
        } else if (req === '3'){
            xmlhttp.onreadystatechange = handleServerResponseOTP;
        } else if (req === '5'){
            xmlhttp.onreadystatechange = handleServerResponseCR;
        } else if (req === '6'){
            xmlhttp.onreadystatechange = handleServerResponsePKI;
        } else if (req === '9'){
            xmlhttp.onreadystatechange = handleServerResponseSign;
        }
        xmlhttp.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded;text/xml;charset=UTF-8');
        xmlhttp.send();
    } else
    {
        alert("xmlhttp is false");
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

function handleServerResponseQR() {   //QR Code handler

    if (xmlhttp.readyState === 4) {
        if (xmlhttp.status === 200) {

            var response = xmlhttp.responseText;
            console.log(response);
            if (document.getElementById('reqCode').value === "1") {

                if (response === "1") {
                    log = document.getElementById('consolelog').value;
                    log = log + "<br>" + d.toLocaleString() + " : " + "Transaction Error";
                    document.getElementById('consolelog').value = log;
                    document.getElementById('displayconsolelog').innerHTML = log;

                    document.getElementById('error-message').style.display = 'block';
                    document.getElementById('error-text').innerHTML = "Transaction Error";
                    setTimeout(function () {
                        document.getElementById('error-message').style.display = 'none';
                        window.location = (getBaseURL() + "/login.jsp");
                    }, 5000);
                } else {
                    window.location = (getBaseURL() + "/main.jsp");
                }
            } else {
                if (response === "error")
                {
                    log = document.getElementById('consolelog').value;
                    log = log + "<br>" + d.toLocaleString() + " : " + "QR Code Request Failed";
                    document.getElementById('consolelog').value = log;
                    document.getElementById('displayconsolelog').innerHTML = log;

                    document.getElementById('fade').style.display = 'block';
                    document.getElementById('error-message').style.display = 'block';
                    document.getElementById('error-text').innerHTML = "QR Code Request Failed";
                    setTimeout(function () {
                        document.getElementById('error-message').style.display = 'none';
                        window.location = (getBaseURL() + "/main.jsp");
                    }, 5000);
                } else {                   
                        
                    //server response contains 2 value separated by delimeter "||"
                    var respondString = response.split("||");
                    document.getElementById("qrCode").src = "./qrcode?qrtext=" + encodeURIComponent(respondString[0]);
                    document.getElementById('qrCodeDisplay').style.display = 'table-row';
                    //document.getElementById('qr_click_row').style.display = 'table-row';
                    //document.getElementById('otpChallengeDisplay').innerHTML =respondString[1];
                    username = document.getElementById('userid').value;

                    loginStateCheckService = setInterval(function () {
                        refreshAuthState();
                    }, interval);
                    log = document.getElementById('consolelog').value;
                    log = log + "<br>" + d.toLocaleString() + " : " + "QR Code Request Successfully";
                    document.getElementById('consolelog').value = log;
                    document.getElementById('displayconsolelog').innerHTML = log;

                    document.getElementById('success-message-noclose').style.display = 'block';
                    document.getElementById('success-text-noclose').innerHTML = "QR Code Request Successfully. Please scan this QR Code for transaction verification...";                        
                }                
            }
        } else {
            document.getElementById('error-message').style.display = 'block';
            document.getElementById('error-text').innerHTML = "Error during AJAX call. Please try again";
            setTimeout(function () {
                document.getElementById('error-message').style.display = 'none';
            }, 2000);
        }
    }
}

function handleServerResponsePushCr() {//Mobile Push handler

    if (xmlhttp.readyState === 4) {
        if (xmlhttp.status === 200) {

            var response = xmlhttp.responseText;
            
                if (response === "error")
                {
                    log = document.getElementById('consolelog').value;
                    log = log + "<br>" + d.toLocaleString() + " : " + "Mobile Push Request Failed";
                    document.getElementById('consolelog').value = log;
                    document.getElementById('displayconsolelog').innerHTML = log;

                    document.getElementById('fade').style.display = 'block';
                    document.getElementById('error-message').style.display = 'block';
                    document.getElementById('error-text').innerHTML = "Mobile Push Request Failed";
                    setTimeout(function () {
                        document.getElementById('error-message').style.display = 'none';
                        window.location = (getBaseURL() + "/main.jsp");
                    }, 5000);
                } else {

                    username = document.getElementById('userid').value;

                    loginStateCheckService = setInterval(function () {
                        refreshAuthState();
                    }, interval);
                    
                    log = document.getElementById('consolelog').value;
                    log = log + "<br>" + d.toLocaleString() + " : " + "Mobile Push Request Successfully";
                    document.getElementById('consolelog').value = log;
                    document.getElementById('displayconsolelog').innerHTML = log;

                    document.getElementById('success-message-noclose').style.display = 'block';
                    document.getElementById('success-text-noclose').innerHTML = "Mobile Push Request Successfully. Please check your mobile device for transaction verification...";
                    
                }
            
        } else {
            document.getElementById('error-message').style.display = 'block';
            document.getElementById('error-text').innerHTML = "Error during AJAX call. Please try again";
            setTimeout(function () {
                document.getElementById('error-message').style.display = 'none';
            }, 2000);
        }
    }
}

function handleServerResponseSMS() {//SMS handler

    if (xmlhttp.readyState === 4) {
        if (xmlhttp.status === 200) {

            var response = xmlhttp.responseText;
            
                if (response === "error")
                {
                    log = document.getElementById('consolelog').value;
                    log = log + "<br>" + d.toLocaleString() + " : " + "SMS Request Failed";
                    document.getElementById('consolelog').value = log;
                    document.getElementById('displayconsolelog').innerHTML = log;

                    document.getElementById('fade').style.display = 'block';
                    document.getElementById('error-message').style.display = 'block';
                    document.getElementById('error-text').innerHTML = "SMS Request Failed";
                    setTimeout(function () {
                        document.getElementById('error-message').style.display = 'none';
                        window.location = (getBaseURL() + "/main.jsp");
                    }, 5000);
                } else {

                    username = document.getElementById('userid').value;                  
                    document.getElementById('tac_click_row').style.display = 'table-row';                  
                    document.getElementById('tacDisplay').innerHTML = 'SMS';                    

                    loginStateCheckService = setInterval(function () {
                        refreshAuthState();
                    }, interval);                    
                    
                    log = document.getElementById('consolelog').value;
                    log = log + "<br>" + d.toLocaleString() + " : " + "SMS Request Successfully";
                    document.getElementById('consolelog').value = log;
                    document.getElementById('displayconsolelog').innerHTML = log;

                    document.getElementById('success-message-noclose').style.display = 'block';
                    document.getElementById('success-text-noclose').innerHTML = "SMS Request Successfully. Please enter SMS for transaction verification...";
                    showTACInput();                    
                }
            
        } else {
            document.getElementById('error-message').style.display = 'block';
            document.getElementById('error-text').innerHTML = "Error during AJAX call. Please try again";
            setTimeout(function () {
                document.getElementById('error-message').style.display = 'none';
            }, 2000);
        }
    }
}

function handleServerResponseOTP() {//OTP handler

    if (xmlhttp.readyState === 4) {
        if (xmlhttp.status === 200) {

            var response = xmlhttp.responseText;
            
                if (response === "error")
                {
                    log = document.getElementById('consolelog').value;
                    log = log + "<br>" + d.toLocaleString() + " : " + "OTP Request Failed";
                    document.getElementById('consolelog').value = log;
                    document.getElementById('displayconsolelog').innerHTML = log;

                    document.getElementById('fade').style.display = 'block';
                    document.getElementById('error-message').style.display = 'block';
                    document.getElementById('error-text').innerHTML = "OTP Request Failed";
                    setTimeout(function () {
                        document.getElementById('error-message').style.display = 'none';
                        window.location = (getBaseURL() + "/main.jsp");
                    }, 5000);
                } else {

                    username = document.getElementById('userid').value;
       
                    document.getElementById('tac_click_row').style.display = 'table-row';                  
                    document.getElementById('tacDisplay').innerHTML = 'OTP';
                    username = document.getElementById('userid').value;

                    loginStateCheckService = setInterval(function () {
                        refreshAuthState();
                    }, interval);
                 
                    log = document.getElementById('consolelog').value;
                    log = log + "<br>" + d.toLocaleString() + " : " + "OTP Request Successfully";
                    document.getElementById('consolelog').value = log;
                    document.getElementById('displayconsolelog').innerHTML = log;

                    document.getElementById('success-message-noclose').style.display = 'block';
                    document.getElementById('success-text-noclose').innerHTML = "OTP Request Successfully. Please enter OTP for transaction verification...";
                    showTACInput();
                }
            
        } else {
            document.getElementById('error-message').style.display = 'block';
            document.getElementById('error-text').innerHTML = "Error during AJAX call. Please try again";
            setTimeout(function () {
                document.getElementById('error-message').style.display = 'none';
            }, 2000);
        }
    }
}

function handleServerResponseSign(){ //Signing OTP
    if (xmlhttp.readyState === 4) {
        if (xmlhttp.status === 200) {

            var response = xmlhttp.responseText;
            
                if (response === "error")
                {
                    log = document.getElementById('consolelog').value;
                    log = log + "<br>" + d.toLocaleString() + " : " + "Signing OTP Request Failed";
                    document.getElementById('consolelog').value = log;
                    document.getElementById('displayconsolelog').innerHTML = log;

                    document.getElementById('fade').style.display = 'block';
                    document.getElementById('error-message').style.display = 'block';
                    document.getElementById('error-text').innerHTML = "Signing OTP Request Failed";
                    setTimeout(function () {
                        document.getElementById('error-message').style.display = 'none';
                        window.location = (getBaseURL() + "/main.jsp");
                    }, 5000);
                } else {
                    
                    username = document.getElementById('userid').value;
                    document.getElementById('tac_click_row').style.display = 'table-row';
                    document.getElementById('tacDisplay').innerHTML = 'Signing OTP';
                    //server response is otpChallenge
                    //document.getElementById('input0').style.display='table-row';
                    document.getElementById('challengeDisplay').innerHTML = 'Challenge';           
                    document.getElementById('otpChallengeDisplay').innerHTML = response;   

                    loginStateCheckService = setInterval(function () {
                        refreshAuthState();
                    }, interval);
                    
                    log = document.getElementById('consolelog').value;
                    log = log + "<br>" + d.toLocaleString() + " : " + "Signing OTP Request Successfully";
                    document.getElementById('consolelog').value = log;
                    document.getElementById('displayconsolelog').innerHTML = log;

                    document.getElementById('success-message-noclose').style.display = 'block';
                    document.getElementById('success-text-noclose').innerHTML = "Signing OTP Request Successfully. Please enter CR OTP for transaction verification...";  
                    showTACInput();
                }
            
        } else {
            document.getElementById('error-message').style.display = 'block';
            document.getElementById('error-text').innerHTML = "Error during AJAX call. Please try again";
            setTimeout(function () {
                document.getElementById('error-message').style.display = 'none';
            }, 2000);
        }
    }
}

function handleServerResponseCR() {//CR handler

    if (xmlhttp.readyState === 4) {
        if (xmlhttp.status === 200) {

            var response = xmlhttp.responseText;
            
                if (response === "error")
                {
                    log = document.getElementById('consolelog').value;
                    log = log + "<br>" + d.toLocaleString() + " : " + "CROTP Request Failed";
                    document.getElementById('consolelog').value = log;
                    document.getElementById('displayconsolelog').innerHTML = log;

                    document.getElementById('fade').style.display = 'block';
                    document.getElementById('error-message').style.display = 'block';
                    document.getElementById('error-text').innerHTML = "CROTP Request Failed";
                    setTimeout(function () {
                        document.getElementById('error-message').style.display = 'none';
                        window.location = (getBaseURL() + "/main.jsp");
                    }, 5000);
                } else {
                    
                    username = document.getElementById('userid').value;
                    document.getElementById('tac_click_row').style.display = 'table-row';
                    document.getElementById('tacDisplay').innerHTML = 'CR OTP';
                    //server response is otpChallenge
                    //document.getElementById('input0').style.display='table-row';
                    document.getElementById('challengeDisplay').innerHTML = 'Challenge';           
                    document.getElementById('otpChallengeDisplay').innerHTML = response;   

                    loginStateCheckService = setInterval(function () {
                        refreshAuthState();
                    }, interval);
                    
                    log = document.getElementById('consolelog').value;
                    log = log + "<br>" + d.toLocaleString() + " : " + "CROTP Request Successfully";
                    document.getElementById('consolelog').value = log;
                    document.getElementById('displayconsolelog').innerHTML = log;

                    document.getElementById('success-message-noclose').style.display = 'block';
                    document.getElementById('success-text-noclose').innerHTML = "CROTP Request Successfully. Please enter CR OTP for transaction verification...";  
                    showTACInput();
                }
            
        } else {
            document.getElementById('error-message').style.display = 'block';
            document.getElementById('error-text').innerHTML = "Error during AJAX call. Please try again";
            setTimeout(function () {
                document.getElementById('error-message').style.display = 'none';
            }, 2000);
        }
    }
}

function onSignCallback(status, signature, plainText, username) {
    console.log(plainText);
    console.log(username);
    var url = getBaseURL() + "/PKILoginServlet?REQ=6&consolelog=" + document.getElementById('consolelog').value
            +"&username="+username+"&plainText="+plainText;
    $.ajaxSetup({
        cache: false
    });
    var data =  {
            username: username,
            signature: signature,
            plainText: plainText
        };
     

    $.ajax({
        url: url,
        data: data,
        type: "POST",
        async: false
    }).done(function (result) {
        console.log(result);
        if (result === "error")
        {
            log = document.getElementById('consolelog').value;
            log = log + "<br>" + d.toLocaleString() + " : " + "PKI Login Failed";
            document.getElementById('consolelog').value = log;
            document.getElementById('displayconsolelog').innerHTML = log;

            document.getElementById('fade').style.display = 'block';
            document.getElementById('error-message').style.display = 'block';
            document.getElementById('error-text').innerHTML = "PKI Login Failed";
            setTimeout(function () {
                document.getElementById('error-message').style.display = 'none';
                window.location = (getBaseURL() + "/main.jsp");
            }, 5000);
        } else {

            username = document.getElementById('userid').value;

            loginStateCheckService = setInterval(function () {
                clearInterval(loginStateCheckService);
                setMessage("1");
            }, 2000);

            log = document.getElementById('consolelog').value;
            log = log + "<br>" + d.toLocaleString() + " : " + "PKI Login Successfully";
            document.getElementById('consolelog').value = log;
            document.getElementById('displayconsolelog').innerHTML = log;

            document.getElementById('success-message-noclose').style.display = 'block';
            document.getElementById('success-text-noclose').innerHTML = "PKI Login Successfully. Please wait for transaction verification...";

        }
    }).fail(function () {
        handleServerResponsePKI();
    });
}

function handleServerResponsePKI() {//PKI handler

    if (xmlhttp.readyState === 4) {
        if (xmlhttp.status === 200) {

            var response = xmlhttp.responseText;

            if (response === "error")
            {
                log = document.getElementById('consolelog').value;
                log = log + "<br>" + d.toLocaleString() + " : " + "PKI Login Failed";
                document.getElementById('consolelog').value = log;
                document.getElementById('displayconsolelog').innerHTML = log;

                document.getElementById('fade').style.display = 'block';
                document.getElementById('error-message').style.display = 'block';
                document.getElementById('error-text').innerHTML = "PKI Login Failed";
                setTimeout(function () {
                    document.getElementById('error-message').style.display = 'none';
                    window.location = (getBaseURL() + "/main.jsp");
                }, 5000);
            } else {

                username = document.getElementById('userid').value;

                loginStateCheckService = setInterval(function () {
                    clearInterval(loginStateCheckService);
                    setMessage("1");
                }, 2000);

                log = document.getElementById('consolelog').value;
                log = log + "<br>" + d.toLocaleString() + " : " + "PKI Login Successfully";
                document.getElementById('consolelog').value = log;
                document.getElementById('displayconsolelog').innerHTML = log;

                document.getElementById('success-message-noclose').style.display = 'block';
                document.getElementById('success-text-noclose').innerHTML = "PKI Login Successfully. Please wait for transaction verification...";

            }

        } else {
            document.getElementById('error-message').style.display = 'block';
            document.getElementById('error-text').innerHTML = "Error during AJAX call. Please try again";
            setTimeout(function () {
                document.getElementById('error-message').style.display = 'none';
            }, 2000);
        }
    }
}

function showTACInput() {    
    document.getElementById('tac_click_row').style.display='none';
    document.getElementById('tac_info_row').style.display='table-row';
    document.getElementById('input1').style.display='table-row';  
    document.getElementById('input0').style.display='table-row';     
    window.document.FORM.tac.className="mandatory";
    clearInterval(loginStateCheckService);
    return;
}

function getInvokeTAC(mode, username, tac, challenge) {
    var url = getBaseURL() + "/TransServlet?MODE=" + mode + "&userid=" + username + "&tac=" + tac + "&challenge=" + challenge + "&consolelog=" + document.getElementById('consolelog').value + "&browserfp=" + document.getElementById('browserfp').value;
    if (xmlhttp) {
        xmlhttp.open("GET", url, false);
        xmlhttp.onreadystatechange = handleServerResponseTAC;
        xmlhttp.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded;text/xml;charset=UTF-8');
        xmlhttp.send();
    } else
    {
        alert("xmlhttp is false");
    }
}

function handleServerResponseTAC() {

    if (xmlhttp.readyState === 4) {
        if (xmlhttp.status === 200) {

            var response = xmlhttp.responseText;
            if (response === "0") {
                setMessage("1");
            } else {
                setMessage("2");
            }
        } else {
            setMessage("2");
        }
    }
}

function refreshAuthState() {
    var dt = new Date();
    var ajax = dt.getTime();
    var url = "./restfulUtil?ajax=" + ajax + "&mode=refreshauthstate";
    $.ajaxSetup({
        cache: false
    });

    $.ajax({
        url: url,
        type: "POST",
        timeout: 5000
    }).done(function (output) {
        var response = output.split("|");
        if (response[0] === "1") {
            clearInterval(loginStateCheckService);
            setMessage("1");
        } else if (response[0] === "2") {
            //pending. do nothing
        } else if (response[0] === "3") {
            //multi-step
            clearInterval(loginStateCheckService);
            setMessage("1");
        } else if (response[0] === "0") {
            //failed
            clearInterval(loginStateCheckService);
            setMessage("2");
        } else if (response[0] === "-1") {
            //failed
            clearInterval(loginStateCheckService);
            setMessage("2");
        } else {
            //failed
            clearInterval(loginStateCheckService);
            setMessage("2");
        }
    }).fail(function (jqXHR, textStatus, errorThrown) {
        // log the error to the console
        console.error(
                "The following error occured: " +
                textStatus, errorThrown
                );
    });
}

function setMessage(status)
{
    if (status === "1") {
        document.getElementById('success-message-noclose').style.display = 'none';
        log = document.getElementById('consolelog').value;
        log = log + "<br>" + d.toLocaleString() + " : " + "Transaction Complete Successfully";
        document.getElementById('consolelog').value = log;
        document.getElementById('displayconsolelog').innerHTML = log;

        document.getElementById('fade').style.display = 'block';
        document.getElementById('success-message').style.display = 'block';
        document.getElementById('success-text').innerHTML = "Transaction Complete Successfully";
        

        setTimeout(function () {
            document.getElementById('success-message').style.display = 'none';
            window.location.replace(getBaseURL() + "/main.jsp");
        }, 5000);
    } else {
        document.getElementById('success-message-noclose').style.display = 'none';
        log = document.getElementById('consolelog').value;
        log = log + "<br>" + d.toLocaleString() + " : " + "Transaction Failed";
        document.getElementById('consolelog').value = log;
        document.getElementById('displayconsolelog').innerHTML = log;

        document.getElementById('fade').style.display = 'block';
        document.getElementById('error-message').style.display = 'block';
        document.getElementById('error-text').innerHTML = "Transaction Failed";
        setTimeout(function () {
            document.getElementById('error-message').style.display = 'none';
            window.location.replace(getBaseURL() + "/main.jsp");
        }, 5000);
    }
}

function msgbox(type, message) {

    if (type === '1') {
        document.getElementById('fade').style.display = 'block';
        document.getElementById('error-message').style.display = 'block';
        document.getElementById('error-text').innerHTML = message;

        setTimeout(function () {
            document.getElementById('error-message').style.display = 'none';
            document.getElementById('fade').style.display = 'none';
        }, 2000);
    } else if (type === '2') {
        document.getElementById('fade').style.display = 'block';
        document.getElementById('success-message').style.display = 'block';
        document.getElementById('success-text').innerHTML = message;

        setTimeout(function () {
            document.getElementById('success-message').style.display = 'none';
            document.getElementById('fade').style.display = 'none';
        }, 2000);
    }
}


function backtomain()
{
    window.location.replace(getBaseURL() + "/main.jsp");
}

function backtoRegister()
{
    window.location.replace(getBaseURL() + "/selfregister.jsp");
}






    