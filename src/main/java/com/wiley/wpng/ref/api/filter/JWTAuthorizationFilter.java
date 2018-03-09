package com.wiley.wpng.ref.api.filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.GeneralJwtException;
import org.jose4j.jwt.JwtClaims;

import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    private static Log log = LogFactory.getLog(JWTAuthorizationFilter.class);


    private Map<String, HttpsJwksVerificationKeyResolver> jksMap = new HashMap<>();

    public static final String HEADER_STRING = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";

    private String auth0JwksEndpoint = "https://parkerneff.auth0.com/.well-known/jwks.json";


    // Get the key resolver from the jwks endpoint
    HttpsJwks httpsJkws = new HttpsJwks("https://localhost:8443/cas/oidc/jwks");

    HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);


    String issuer = "http://localhost:8080/cas/oidc";
    String audience = "reference_client";

    //    public JWTAuthorizationFilter(AuthenticationManager authManager) {
//        super(authManager);
//    }
    public JWTAuthorizationFilter(AuthenticationManager authManager, Map<String, String> issuerMap) {
        super(authManager);
        //this.issuerMap = issuerMap;
        log.info("Creating web filter");

        for (String key : issuerMap.keySet()) {
            log.info("adding JWKS Key Resolver entry " + key + "=" + issuerMap.get(key));
            jksMap.put(key, new HttpsJwksVerificationKeyResolver(new HttpsJwks(issuerMap.get(key))));
        }
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
        String rawToken = request.getHeader(HEADER_STRING);
        if (rawToken != null) {
            String token = rawToken.replace(TOKEN_PREFIX, "");
            log.debug("Authorizing token: " + token);

            try {
                JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                        .setRequireExpirationTime() // the JWT must have an expiration time
                        .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                        .setRequireSubject() // the JWT must have a subject claim
                        .setSkipDefaultAudienceValidation() // TODO Determine if audience check really is required
                        //.setExpectedAudience(false, "tiOFA1XX0w6g4exs1FQVEBkcCTcr7zEu") // to whom the JWT is intended for
                        .setVerificationKeyResolver(getJwtKeyResolver(token))
                        .build(); // create the JwtConsumer instance


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

    /*
    Get the issuer from the JWT so we can determine which key to validate with
     */
    private HttpsJwksVerificationKeyResolver getJwtKeyResolver(String token) throws Exception {
        // Build a JwtConsumer that doesn't check signatures or do any validation.
        JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        //The first JwtConsumer is basically just used to parse the JWT into a JwtContext object.
        JwtContext jwtContext = firstPassJwtConsumer.process(token);

        // From the JwtContext we can get the issuer, or whatever else we might need,
        // to lookup or figure out the kind of validation policy to apply
        String issuer = jwtContext.getJwtClaims().getIssuer();
        log.debug("Finding JKS Resolver entry for issuer " + issuer);
        if (StringUtils.isEmpty(issuer)) {
            throw new Exception("Could not parse issuer from JWT");
        }
        if (!jksMap.containsKey(issuer)) {
            throw new Exception("Issuer " + issuer + " is not configured to JKS Map");
        }
        return jksMap.get(issuer);


    }
}
