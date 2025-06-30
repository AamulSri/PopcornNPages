package com.popcornNpages.popcornNpages.utility;


import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class PasswordHashingAndComparision {
     private final BCryptPasswordEncoder encode = new BCryptPasswordEncoder();
    
    public String passwordEndocder(String password){
        String hashedPassword = encode.encode(password);
        return hashedPassword;
    }

    public Boolean verfiyPassword(String rawPassword , String hashPassword ){
        Boolean res = false;
        res = encode.matches(rawPassword, hashPassword);
        return res;
    }


}
