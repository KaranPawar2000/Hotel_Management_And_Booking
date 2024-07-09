package com.hotel_management.karan.security;

import com.hotel_management.karan.service.CustomUserDetailsService;
import com.hotel_management.karan.utils.JWTUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.CachingUserDetailsService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JWTAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JWTUtils jwtUtils;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization"); //header contains key value pair Authorization key contains token
        final String jwtToken;
        final String userEmail;

        if (authHeader==null || authHeader.isBlank()){
            filterChain.doFilter(request,response);
            return;
        }

        jwtToken =authHeader.substring(7);
        userEmail=jwtUtils.extractUsername(jwtToken);

        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){ //If the username is not null and there is no existing authentication, the user details are loaded.
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(userEmail);
            if(jwtUtils.isValidToken(jwtToken,userDetails)){
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                securityContext.setAuthentication(token);
                SecurityContextHolder.setContext(securityContext);
            }
        }
        filterChain.doFilter(request,response);

    }

}
/*
SecurityContextHolder: This is a central class in Spring Security that holds the security context of the current thread. It manages the security context, which includes details about the authenticated principal (user) and their granted authorities.

createEmptyContext(): This method creates a new, empty SecurityContext instance. An empty context means that it does not contain any authenticated user information or granted authorities initially.

SecurityContext securityContext = ...;: This line declares a variable securityContext of type SecurityContext and initializes it with the newly created empty security context.

Purpose and Usage
In the context of Spring Security and specifically within the JWTAuthFilter class:

Authentication Flow:

When a request is intercepted by JWTAuthFilter, it extracts the JWT token from the Authorization header, validates it, and determines the associated user details (typically fetched from a database via CustomUserDetailsService).
Creating a Security Context:

If the JWT token is valid and there is no existing authentication context (SecurityContextHolder.getContext().getAuthentication() == null), a new SecurityContext is created.
Setting Authentication Information:

Once the SecurityContext is created, an Authentication object (UsernamePasswordAuthenticationToken in this case) is constructed using the validated user details and set within the SecurityContext.
Associating with SecurityContextHolder:

Finally, the securityContext is set as the current security context using SecurityContextHolder.setContext(securityContext). This makes the authenticated user and their granted authorities available for the current thread's execution context.
Why Create an Empty Context?
Starting Fresh: Creating an empty SecurityContext ensures that no previous authentication state interferes with the current request's authentication process.

Thread Safety: Each thread in a Java application has its own SecurityContextHolder, and creating an empty context ensures thread safety and avoids unintentional sharing of security context state across threads.

        Summary
The line SecurityContext securityContext = SecurityContextHolder.createEmptyContext(); initializes a new, empty security context within the JWTAuthFilter class. This context serves as a container for authentication information (such as the authenticated user and their authorities) during the authentication process based on the JWT token provided in the request. It ensures that subsequent operations within the application can securely access and verify the authenticated user's identity and authorization levels.


UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
ChatGPT
The line UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()); within the JWTAuthFilter class plays a pivotal role in Spring Security's authentication mechanism, especially when integrating with JWT-based authentication. Let's delve into what this line accomplishes and its significance:

Explanation
        java
Copy code
UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
UsernamePasswordAuthenticationToken: This class is a specialization of AbstractAuthenticationToken provided by Spring Security. It represents an authentication request containing the principal (typically UserDetails), credentials (which can be null in this case since JWT serves as the credential), and the authorities granted to the principal.

        Parameters:

userDetails: This is an instance of UserDetails, typically retrieved from a user service (CustomUserDetailsService) based on the username extracted from the JWT token. UserDetails contains information about the authenticated user, such as username, password (which is not used directly in JWT-based auth), and granted authorities.

        null: Represents the credentials associated with the principal. In JWT-based authentication, the token itself acts as the credential, so null is passed here.

        userDetails.getAuthorities(): This retrieves the authorities granted to the authenticated user. Authorities define what actions or resources the user is allowed to access within the application.

        Purpose
Authentication Token Construction: The UsernamePasswordAuthenticationToken is used to encapsulate the authenticated user's principal (userDetails), credentials (typically null in JWT-based auth), and authorities (userDetails.getAuthorities()).

Integration with Spring Security: This token integrates seamlessly with Spring Security's authentication framework. It allows Spring Security to recognize and process the authenticated user within its security context.

Setting Authentication Details: Once constructed, this token is set as part of the SecurityContext to establish the authenticated user for the current request, ensuring that subsequent operations within the application can securely access and verify the user's identity and permissions.

Usage Context
In the JWTAuthFilter class, this token is typically used after verifying the JWT token's validity and extracting the associated UserDetails from the CustomUserDetailsService. It signifies that the user identified by the JWT token is now authenticated within the application's security framework.

        Summary
The line UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()); constructs an authentication token representing a user authenticated via JWT-based authentication. It encapsulates the user's details and authorities, enabling Spring Security to manage and enforce access control based on the user's authenticated identity.

*/





