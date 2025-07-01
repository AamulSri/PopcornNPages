package com.popcornNpages.AuthService.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.popcornNpages.AuthService.dto.LoginRequest;
import com.popcornNpages.AuthService.dto.LoginResponse;
import com.popcornNpages.AuthService.dto.RegisterRequest;
import com.popcornNpages.AuthService.services.AuthService;


@RestController
public class AuthController {
    
    @Autowired
    AuthService authService;

    @PostMapping("/auth/register")
    public String registerUser(@RequestBody RegisterRequest user){
        authService.registerUser(user);
        return "User Registered " + user.getEmail();
    }

    @PostMapping("/auth/login")
    public ResponseEntity<LoginResponse> userlogin(@RequestBody LoginRequest login ){
      return  authService.userLogin(login);
     
    }
}
