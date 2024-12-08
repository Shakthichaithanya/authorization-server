package com.authorization.server.model;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.mongodb.core.mapping.Document;


import java.time.Instant;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Document(collection = "clients")
public class Client {

    @Id
    private String id;

    private String clientId;

    private Instant clientIdIssuedAt;

    private String clientSecret;

    private Instant clientSecretExpiresAt;

    private String clientName;

    private Set<String> clientAuthenticationMethods;

    private Set<String> authorizationGrantTypes;

    private Set<String> redirectUris;

    private Set<String> postLogoutRedirectUris;

    private Set<String> scopes;

}
