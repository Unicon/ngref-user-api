package com.wiley.wpng.ref.api;

import com.wiley.wpng.ref.api.filter.JWTAuthorizationFilter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.HashMap;
import java.util.Map;


@ConfigurationProperties(prefix = "oidc")
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {
    private Log log = LogFactory.getLog(WebSecurity.class);



    private Map<String, String> oidcIssuers = new HashMap<>();

    public Map<String, String> getOidcIssuers() {
        return oidcIssuers;
    }

    public void setOidcIssuers(Map<String, String> oidcIssuers) {
        this.oidcIssuers = oidcIssuers;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        log.info("!!!!!!!!! Issuers = " + getOidcIssuers().toString());
        if (oidcIssuers != null) {
            for (String key : oidcIssuers.keySet()) {
                log.info("key: " + key + " value: " + oidcIssuers.get(key));
            }

        }
        http.cors().and().csrf().disable().authorizeRequests()
                .antMatchers(HttpMethod.POST, "/user/auth").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilter(jwtAuthorizationFilter())
                // this disables session creation on Spring Security
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }



    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
        return source;
    }

    private JWTAuthorizationFilter jwtAuthorizationFilter() throws Exception {


        JWTAuthorizationFilter filter = new JWTAuthorizationFilter(authenticationManager(), oidcIssuers);
        return filter;

    }
}