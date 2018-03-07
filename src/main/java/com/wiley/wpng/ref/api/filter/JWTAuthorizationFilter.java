package com.wiley.wpng.ref.api.filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.JwtClaims;

import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    private static Log log = LogFactory.getLog(JWTAuthorizationFilter.class);

    public static final String HEADER_STRING = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";


    // Get the key resolver from the jwks endpoint
    HttpsJwks httpsJkws = new HttpsJwks("https://localhost:8443/cas/oidc/jwks");

    HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);

    String issuer = "http://localhost:8080/cas/oidc";
    String audience = "reference_client";

    public JWTAuthorizationFilter(AuthenticationManager authManager) {
        super(authManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {

        String header = req.getHeader(HEADER_STRING);
        log.debug("Raw Token Info: " + header);

        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }


        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(HEADER_STRING);
        if (token != null) {

            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                    .setRequireExpirationTime() // the JWT must have an expiration time
                    .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                    .setRequireSubject() // the JWT must have a subject claim
                    .setExpectedIssuer(issuer) // whom the JWT needs to have been issued by
                    .setExpectedAudience(audience) // to whom the JWT is intended for
                    .setVerificationKeyResolver(httpsJwksKeyResolver)
                    .build(); // create the JwtConsumer instance

            try {
                JwtClaims jwtClaims = jwtConsumer.processToClaims(token.replace(TOKEN_PREFIX, ""));
                log.debug("got claims: " + jwtClaims.toString());
                String user = jwtClaims.getSubject();
                log.debug("user: " + user);
                if (user != null) {
                    return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
                }
            } catch (Exception e) {
               log.warn(e.getMessage());

            }


            return null;
        } else {
            return null;

        }

    }
}
