package com.popcornNpages.popcornNpages.config;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.popcornNpages.popcornNpages.repository.UserRepository;
import com.popcornNpages.popcornNpages.utility.JWTUtility;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/*GOAL :-
Extracts the token from the request.
Validates that the token follows Bearer <token> format.
Uses JWTUtility to extract the email (subject).
Checks for:
User's existence in DB.
Token validity.
No existing authentication in context.
Wraps the User inside a CustomUserDetails instance.
Creates a Spring Authentication object and sets it in the SecurityContextHolder.
*/

//@Component: This tells Spring to auto-detect and register this class as a bean.
@Component

//extends OncePerRequestFilter: Ensures the filter runs once per request. Ideal for security filters.
public class JWTAuthenticationFilter extends OncePerRequestFilter {
    
    @Autowired
    JWTUtility jwtUtility;

    @Autowired 
    UserRepository userRepository;

    private final Logger log = LoggerFactory.getLogger(JWTUtility.class);

    /*This method is called automatically for every HTTP request.
    request: Incoming HTTP request.
    response: HTTP response to send back.
    filterChain: Allows forwarding the request to the next filter.*/
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    throws ServletException,IOException{

    /*When a user logs in, we give them a "token" (like a digital ID card).
    From then on, every request they send to your app should include 
    this ID card in their Authorization header. 
    So we're saying: "Hey incoming request — do you have your ID card?"*/
        String authHeader = request.getHeader("Authorization");

    /*We're checking two things:
    1.Is there any Authorization header at all?
    authHeader == null
    This checks if the Authorization header is missing in the request.
    If the header is not present, there’s no token to validate,
    so the request is allowed to move on without authentication.

    2.Does it follow the Bearer <token> format?
    JWTs are typically sent like this:
    Authorization: Bearer <your_token_here>
    This part checks if the header starts with Bearer , which is the expected format.
    If it doesn't, it's not a valid JWT request, so we don't process it further.

    The if condition acts like a security guard at the door checking 
    if the person is even carrying something that looks like an ID.
    If not, we just let the request pass without trying to validate anything.

   3. filterChain.doFilter(request, response);
    This passes the request to the next filter or controller in the chain without modifying the security context.
    Meaning: If no valid token → skip JWT auth → let Spring handle it like a public request or deny it later.
   4.return;
   Stops further execution of this filter, since there's no point in parsing an invalid/missing token.
*/
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }

        // Removes "Bearer " from authHeader
        String jwt = authHeader.substring(7); 

        // Extract email from JWT ->
        //That email helps us load the correct user from the database later.
        String userEmail = jwtUtility.extractEmail(jwt); 

        /*userEmail != null: Token was valid and had an email.
        SecurityContextHolder.getContext().getAuthentication() == null: User isn't already authenticated in this request.
        We do this to prevent re-authentication and only do the login logic once.
        */
        if(userEmail!=null && SecurityContextHolder.getContext().getAuthentication()==null){

            /*Even if a token contains a valid email, 
            we must check our database to make sure this user still exists.
            This is how we stay in sync with your real data.*/
            var user = userRepository.findByEmail(userEmail);

           
            /*Two-step final check:
            Does the user exist?
            Is this token valid (not tampered with, not expired)?
            If yes — we trust the token and the user. */
            if(user!=null && jwtUtility.validateToken(jwt)){

                /*Creating a CustomUserDetails because  
                This is how your user model becomes "understood" by Spring Security
                go to the CustomUserDetails and read the goal*/
                CustomUserDetails customUserDetails = new CustomUserDetails(user);


                /*We create a special Spring Security object called Authentication:
                user: The full User object (which should implement UserDetails).
                null: No password is needed here — we’re using a token, not a login form.
                user.getAuthorities(): The user’s roles (like ROLE_USER, ROLE_ADMIN) — needed for authorization later.
                It creates a fully authenticated user that Spring Security can trust for the rest of the request lifecycle.
                It’s like: “Hey Spring, this user is user, no password needed, and they’re allowed to do X, Y, Z.”
                */
                var authToken = new UsernamePasswordAuthenticationToken(customUserDetails,null,customUserDetails.getAuthorities());
                
                /*
                This adds web-specific information like:
                IP address , Session ID (if used)
                It’s useful for auditing or access control logging.
                 */
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                /*This is the key line:
                It tells Spring Security: "Trust this user. They’re authenticated now."
                Spring stores this authToken in a thread-local context,
                so it’s available throughout the request lifecycle.
                From this point onward, your endpoints can use:
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                 */
                SecurityContextHolder.getContext().setAuthentication(authToken); 
                log.info("JWT verified. User authenticated: {}", userEmail);
            }
        }

         /*Always at the end of a filter, 
        you pass control to the next step — either another filter or the controller.*/
             filterChain.doFilter(request, response);
    }

}

    
