package com.purvesh.Authentication.services.implementation;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;


@Service
public class JwtServiceImplementation {


    //this method takes user details, sets various claims
    // (subject, issued-at, expiration), signs the token using a secret key,
    // and returns the final JWT as a string.


    private String generateTokens(UserDetails userDetails)
    {
        return Jwts.builder().setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() +  30L * 24 * 60 * 60 * 1000))
                .signWith(getSignKey() , SignatureAlgorithm.HS256)
                .compact();
    }

    private <T> T extractClaim(String token, Function<Claims , T> claimsResolvers)
    {
        final Claims claims= extractAllClaim(token);
        return claimsResolvers.apply(claims);
    }

    private Key getSignKey(){
        byte[] key = Decoders.BASE64.decode(t:"");//how to get this token from above
        return Keys.hmacShaKeyFor(key);
    }

    private Claims extractAllClaim(String token)
    {
        return Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token).getBody();

    }

    public String extractUserName (String token)
    {
        return extractClaim(token, Claims::getSubject);
    }




}
