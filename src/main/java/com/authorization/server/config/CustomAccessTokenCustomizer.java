package com.authorization.server.config;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

public class CustomAccessTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    @Override
    public void customize(JwtEncodingContext context) {
        if (context.getTokenType().getValue().equals("access_token")) {
            context.getClaims().claim("role", "Admin");
            context.getClaims().claim("sub","shakthi001@gmail.com");
            context.getJwsHeader().header("alg", SignatureAlgorithm.ES256);
//            context.getClaims().claim("roles", context.getPrincipal().getAuthorities());
        }
    }
}
