var fidoResponse;
var fidoReturnMessages = [ "OK" , "OTHER_ERROR" , "BAD_REQUEST" , "CONFIGURATION_UNSUPPORTED" , "DEVICE_INELIGIBLE" , "TIMEOUT" ] ;

function register ( version , challenge , appId , callback )
{
    var regReq = [{
        version: version,
        challenge: challenge,
        appId: appId
    }] ;

    u2f.register ( regReq , [] , callback ) ;
}

function sign ( version , challenge , keyHandle , appId , callback )
{
    var signReq = [{
        version: version,
        challenge: challenge,
        keyHandle: keyHandle,
        appId: appId
    }] ;

    u2f.sign ( signReq , callback ) ;
}
