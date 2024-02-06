package com.purvesh.Authentication.config;


import com.purvesh.Authentication.services.JwtService;
import com.purvesh.Authentication.services.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtservice;
    private final UserService userService;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;


        // If the header is either empty or does not start with "Bearer,"
        // it allows the request to proceed without further authentication processing.


        if (StringUtils.isEmpty(authHeader) || !org.apache.commons.lang3.StringUtils.startsWith(authHeader, "Bearer")) {
            filterChain.doFilter(request, response);
            return;

        }
        jwt=authHeader.substring(7);
        userEmail= jwtservice.extractUserName(jwt);


        if(StringUtils.isNoneEmpty(userEmail)  && SecurityContextHolder.getContext().getAuthentication()==null)
        {
            UserDetails userDetails= userService.userDeatilsService().loadUserByUsername(userEmail);
        }
    }
}
