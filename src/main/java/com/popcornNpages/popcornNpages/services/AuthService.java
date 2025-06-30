package com.popcornNpages.popcornNpages.services;

import java.util.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.popcornNpages.popcornNpages.dto.LoginRequest;
import com.popcornNpages.popcornNpages.dto.RegisterRequest;
import com.popcornNpages.popcornNpages.model.User;
import com.popcornNpages.popcornNpages.model.enums.Role;
import com.popcornNpages.popcornNpages.repository.UserRepository;
import com.popcornNpages.popcornNpages.utility.JWTUtility;
import com.popcornNpages.popcornNpages.utility.PasswordHashingAndComparision;

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

    public ResponseEntity<String> userLogin(LoginRequest login) {
       User user  =  userRepository.findByEmail(login.getEmail());
       if(user!=null && passwordHashingAndComparision.verfiyPassword(login.getPassword(), user.getPassword())){
        String token = jwtUtility.generateToken(user.getEmail());
        return ResponseEntity.ok("Login sucessful with JWT TOKEN" + token);
       }
       return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Credentials");
    }
}
