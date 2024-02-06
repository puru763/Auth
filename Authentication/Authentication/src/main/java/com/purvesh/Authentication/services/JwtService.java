package com.purvesh.Authentication.services;

import org.springframework.security.core.userdetails.UserDetails;

public interface JwtService {



        String extractUserName (String token);

        String generateToken (UserDetails userDetails);

}
