package com.wiley.wpng.ref.api;

import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.fail;

/**
 * Basic integration tests for service demo application.
 *
 * @author Dave Syer
 */

public class RestEndpointTests {


    //@Test
    public void testValidJwk() throws Exception {
        @SuppressWarnings("rawtypes")
// https://localhost:8443/cas/oidc/jwks

                // Get the key resolver from the jwks endpoint
                HttpsJwks httpsJkws = new HttpsJwks("https://parkerneff.auth0.com/.well-known/jwks.json");

        HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);


        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6YzFRVFkyUWpoRU1qTkJOVGxDUkRFNFJFVkdNa1V3TWpWR1JVTkZRalpFTURjeU5rWXpNZyJ9.eyJpc3MiOiJodHRwczovL3Bhcmtlcm5lZmYuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDVhOGYzODhiNzFiYzZkMDIxMjQ4ZmY5YiIsImF1ZCI6InRpT0ZBMVhYMHc2ZzRleHMxRlFWRUJrY0NUY3I3ekV1IiwiaWF0IjoxNTIwNTU0Mjg4LCJleHAiOjE1MjA1OTAyODgsImF0X2hhc2giOiJ2bVFLQThtRDI1ZnExYnhnVG05RDVBIiwibm9uY2UiOiIxMjM0NTYifQ.qdrYIlo6L-7VjXSvAga5SISUJPvypOTMPQ4sMiJykpyriaQykd-Fyec1ezEazL9Pnpbm_zoBwa41e31Wr10HW3uhPbO_XYa5Pfxf0HPLVY-rn_fuWO0rG0Rv80tDp2CDjU11VU6E6cGM7FfqAyhlLTL6kYHY2ZkWuJJ-7YUhzhKvQ9BjE68wTZeXYq2d_kEBPlbTnGz7sXEWeVb7JDgsqbiPbLfy-9whIyPw_sxRJg7FuPmDHaPVYDEUcePOJQjKxX3FSCmaZ44Ec_eVLKAXni1gdAbpxf0zuAjMkG-iXNVFFJMn0ODcIkPi3TANmpnOUFUJ9YCYPLfpzXLPaYPKLA";
        // String issuer = "http://localhost:8080/cas/oidc";
        String issuer = "https://parkerneff.auth0.com/";
        String audience = "tiOFA1XX0w6g4exs1FQVEBkcCTcr7zEu";
//        JwtRequest jwtRequest = new JwtRequest();
//        jwtRequest.setSubject("parkerneff");
//        jwtRequest.setClient("testclient");
//
//
//        jwtRequest.setRoles(new String[]{"admin", "user"});
//        HttpEntity<JwtRequest> request = new HttpEntity<>(jwtRequest);
//        String token = this.testRestTemplate.postForObject("http://localhost:" + this.port + "/token", request, String.class);
//        System.out.println("TOKEN=" + token);
//        assertNotNull(token);



        JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        //The first JwtConsumer is basically just used to parse the JWT into a JwtContext object.

        JwtContext jwtContext = firstPassJwtConsumer.process(token);

        // From the JwtContext we can get the issuer, or whatever else we might need,
        // to lookup or figure out the kind of validation policy to apply


    //String[] audiences = new String[]{"tiOFA1XX0w6g4exs1FQVEBkcCTcr7zEu"};


        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer(issuer) // whom the JWT needs to have been issued by
                //.setSkipDefaultAudienceValidation()
                .setExpectedAudience(false, "tiOFA1XX0w6g4exs1FQVEBkcCTcr7zEu") // to whom the JWT is intended for
                .setVerificationKeyResolver(httpsJwksKeyResolver)
                .build(); // create the JwtConsumer instance


        try {
            JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
        } catch (InvalidJwtException e) {
            fail(e.getMessage());
        }


    }
}
