package com.popcornNpages.AuthService.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.popcornNpages.AuthService.repository.UserRepository;

import lombok.AllArgsConstructor;

/*
The goal of SecurityConfig is to:
    Enable and configure Spring Security.
    Define which endpoints require authentication.
    Plug in JWT-based security (instead of session or form login).
    Register custom filters like your JWTAuthenticationFilter.
    (Optional) Define role-based access control, CORS, CSRF, etc.
 */

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {

    private final JWTAuthenticationFilter jwtFilter;
    private final UserRepository userRepository;
    
    /*@Bean:Tells Spring to treat this method as a configuration bean. 
    The return value (a SecurityFilterChain) is automatically used by Spring Security.
    SecurityFilterChain: This object defines the set of security rules (like who can access what).
    HttpSecurity http: Spring passes in the object you use to configure HTTP-based security.
 */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

        /* 
        1. CSRF = Cross-Site Request Forgery — 
            an attack where a malicious site tricks a user’s browser into making unwanted 
            requests to your site.JWT-based apps don't use sessions or cookies, so CSRF protection is unnecessary.
            Disabling CSRF is safe in stateless REST APIs where auth is done using headers (JWTs), not cookies.

        2.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
         Spring Security by default uses sessions to remember who is logged in.
            But JWT-based systems don’t use sessions at all. Every request is authenticated independently using the token.
            So, we say:
            Don’t create any sessions.
            Each request must be stateless — verified via token.

        3. .authorizeHttpRequests(requests -> requests
            .requestMatchers("/auth/**").permitAll()
            .anyRequest().authenticated()
            )

            a).authorizeHttpRequests(requests -> requests ...)
            What it does: Starts configuring request-level authorization.
            requests -> requests ... is a lambda function used in Spring Security 6+ style.
            You're saying: “Hey Spring Security, let me tell you how to handle different URLs in this app.”

            b).requestMatchers("/auth/**").permitAll()
            Matches any request that starts with /auth/, like:
            /auth/login, /auth/register, /auth/refresh-token (if you add it later)
            Allows access without login or token.
            This is important because you want users to be able to register or log in 
            without being authenticated already.

            c).anyRequest().authenticated()
            This means every other request in your app must be authenticated (i.e., the user must have a valid JWT token).
            So URLs like:
            /movies/review,/books/rate,/user/profile
            Require the token, or Spring Security will block the request.
            
            Summary :- Allow all users to access the authentication endpoints without needing a JWT. 
                       But protect the rest of the app and require a token for everything else.
        
        4. .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
            Spring Security has a chain of filters.
            Your JWTAuthenticationFilter is a custom filter that:
            Reads the token,Validates it,Authenticates the user
            You are saying:
            “Run my JWT filter before Spring's default login filter” 
            (UsernamePasswordAuthenticationFilter), so Spring knows who the user is.

        5  .return http.build();
            Converts all the configuration you’ve written above into a working SecurityFilterChain object.
            Spring Security will use this to apply all the rules and filters to every request.
        */

        http
        .csrf(csrf->csrf.disable())
        .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth.requestMatchers("/auth/**")
        .permitAll()
        .anyRequest().authenticated()
        ).addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // AuthenticationManager is required for login endpoints
    /*Required if you ever want to manually trigger authentication (not needed now but good to keep).
    You may use it if you implement programmatic login in the future. */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
