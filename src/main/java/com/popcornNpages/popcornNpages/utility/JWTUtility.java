package com.popcornNpages.popcornNpages.utility;

import java.security.Key;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;

public class JWTUtility {
     //our secret key 
    private final String secretKey = "p*pc*r*nNp@gesKey$ecretForJwtToken";
   
    // time decided for token to be valid - 1 hr
    private final long expirationTime = 3600000;
   
    //This line generates a secure signing key for the JWT using the HMAC SHA-256 algorithm. 
    //This key is used to sign and later verify your JWTs.
    private final Key key = Keys.hmacShaKeyFor(secretKey.getBytes());

    private static Logger log = LoggerFactory.getLogger(JWTUtility.class);
    

   /*Goal :- It creates a JWT token for a user, embedding their email as the identity,
    setting token validity duration, 
    and digitally signing it using HMAC SHA-256. 
    
    Method Break Down
    1.Jwts.builder() -> Starts creating a new JWT.
    2..setSubject(email)->This sets the "subject" claim of the JWT to the user’s email.
                            Think of it like: “Who is this token about?”
    3..setIssuedAt(new Date())->Adds an "iat" (Issued At) claim.Marks the time when the token was generated.
                                Useful for logging or checking if the token is too old                  
    4..setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))->Adds an "exp" (Expiration) claim.
                                                                            Specifies how long the token is valid.   
    5..signWith(key, SignatureAlgorithm.HS256)->Digitally signs the token using:
                                                Your secret key (HMAC key we discussed earlier).
                                                The HS256 algorithm (HMAC using SHA-256).
                                                Why?
                                                To ensure integrity: No one can change the token 
                                                data without the secret key.
                                                To authenticate: The server later verifies 
                                                this signature to trust the token.  
    6..compact()-> Final step: Converts the token into a compact String format.
    */
    public String generateToken(String email){
        return Jwts
                .builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()+expirationTime))
                .signWith(key,SignatureAlgorithm.HS256)
                .compact();
    }


    /*Goal :- This method validates the JWT token using the secret key and extracts 
    the email (which was stored as the subject during token creation).

    Method BreakDown :-
    1.Jwts.parserBuilder()->Starts building a JWT parser.You use this to verify and decode tokens.

    2. .setSigningKey(key)->You set the same secret key that was used to sign the token during generation.
                            JWT uses this to verify the token's signature.If the token was tampered with, 
                            verification fails.
    3..build()->Finalizes the parser. Only after.build() is called, 
                the parser is ready to actually process/verify tokens.
    4..parseClaimsJws(token)->Actually parses (reads and verifies) the JWT string (token).
                                Jws = "JSON Web Signature" — it checks:
                                The token format.
                                The signature is valid (using the key).
                                The token is not expired.
                                If the token is invalid, this line will throw an exception.

    5..getBody()->If parsing was successful, this gets the payload/claims (the actual data inside the token).
    6..getSubject()->Gets the sub (subject) field from the token — in our case, the user's email.
    */
    public String extractEmail(String token){

            return Jwts
                   .parserBuilder()
                   .setSigningKey(key)
                   .build()
                   .parseClaimsJws(token)
                   .getBody()
                   .getSubject();
    }

    public Boolean validateToken(String token){
        try{
            Jwts
            .parserBuilder() 
            .setSigningKey(key) //Set the secret key used to sign JWT
            .build()          //Finalize parser setup
            .parseClaimsJws(token); //Try parsing and validating the token
            return true;           //Token is Valid
        }
        catch (SecurityException e) {
            log.debug("Invalid JWT signature: " + e.getMessage());
        } catch (MalformedJwtException e) {
            log.debug("Invalid JWT token: " + e.getMessage());
        } catch (ExpiredJwtException e) {
            log.debug("JWT token is expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.debug("JWT token is unsupported: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            log.debug("JWT claims string is empty: " + e.getMessage());
        }
        return false;
    }
}
