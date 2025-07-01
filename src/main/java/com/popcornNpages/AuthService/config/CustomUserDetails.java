package com.popcornNpages.AuthService.config;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.popcornNpages.AuthService.model.User;

import lombok.AllArgsConstructor;

/*
  Goal :-
        To act as a bridge between your custom User entity and Spring Security's internal 
        authentication system, by implementing the UserDetails interface.
        Spring Security works with UserDetails objects, not your actual 
        User entity. So, we wrap your User inside a CustomUserDetails class to:

        Supply username (usually email/username).
        Supply password for login checks.
        Supply authorities/roles for authorization.
        Decide if the account is locked, expired, etc.
        This is how your user model becomes "understood" by Spring Security.
 */
@AllArgsConstructor
public class CustomUserDetails implements UserDetails{

    private User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
  
        return List.of(new SimpleGrantedAuthority("ROLE_"+user.getRole()));
    }

    @Override
    public String getPassword() {
     return user.getPassword();
    }

    @Override
    public String getUsername() {
       
        return user.getEmail();
    }
    
}
