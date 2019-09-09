/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.securemetric.web.api;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author MyPC
 */
public class TestQR {
    public static void main(String args[]) {
        
        String user= "ndthanhadmin";
        String details = "YWJjMTIz";
        String unixTimestamp = String.valueOf ( System.currentTimeMillis ( ) / 1000L ) ;  
        //office thanh
        //String secretKey = "p98rjXh03qHX";
        //String integrationKey = "ee9228e350b10b744aff1135e01f3d1c858bcd25e84dd7038946bdb73144653d";
        
        //office tirta
        //String secretKey = "p9ZkmsvbsQgG";
        //String integrationKey = "dc11c37d776c4afd56b3bc0f2d3be1f8236e36ae2a6d7870fbbd2d9160599e5e";
        //OCB
        String secretKey = "p98rjXh03qHX";
        String integrationKey = "ee9228e350b10b744aff1135e01f3d1c858bcd25e84dd7038946bdb73144653d";
        details = Base64.encodeBase64String("abcdef".getBytes());
    }
}
