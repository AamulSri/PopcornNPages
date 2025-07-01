package com.popcornNpages.AuthService.services;

import java.util.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.popcornNpages.AuthService.dto.LoginRequest;
import com.popcornNpages.AuthService.dto.LoginResponse;
import com.popcornNpages.AuthService.dto.RegisterRequest;
import com.popcornNpages.AuthService.model.User;
import com.popcornNpages.AuthService.model.enums.Role;
import com.popcornNpages.AuthService.repository.UserRepository;
import com.popcornNpages.AuthService.utility.JWTUtility;
import com.popcornNpages.AuthService.utility.PasswordHashingAndComparision;


@Service

public class AuthService {

    @Autowired
    PasswordHashingAndComparision passwordHashingAndComparision;

    @Autowired
    UserRepository userRepository;

    @Autowired
    JWTUtility jwtUtility;


    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
   
    public User registerUser( RegisterRequest registerRequest){
        User user = new User();
        user.setFirstName(registerRequest.getFirstName());
        user.setLastName(registerRequest.getLastName());
        user.setEmail(registerRequest.getEmail());
        user.setRole(Role.USER);
        user.setPassword(passwordHashingAndComparision.passwordEndocder(registerRequest.getPassword()));
        return userRepository.save(user);

    }

    public ResponseEntity<LoginResponse> userLogin(LoginRequest login) {
        LoginResponse loginResponse = new LoginResponse();
       User user  =  userRepository.findByEmail(login.getEmail());
       if(user!=null && passwordHashingAndComparision.verfiyPassword(login.getPassword(), user.getPassword())){
        loginResponse.setToken(jwtUtility.generateToken(user.getEmail()));
        return ResponseEntity.ok(loginResponse);
       }
       /*HttpStatus.UNAUTHORIZED = 401 status code.
       .body() returns an error msg  */
       loginResponse.setErrorMessage("Invalid Credentials");
       return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(loginResponse);
    }
}
