package com.authorization.server.controller;

import com.authorization.server.model.Client;
import com.authorization.server.repository.ClientRepository;
import com.authorization.server.repository.DynamicClientRegistrationRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/")
public class ClientRegistrationController {

    private final ClientRepository clientRepository;

    public ClientRegistrationController(ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

//    @PostMapping
//    public ResponseEntity<Client> registerClient(@RequestBody Client clientRequest) {
//        // Generate a unique clientId and clientSecret if not provided
//
//        // Save to the database
//        Client savedClient = clientRepository.save(clientRequest);
//
//        // Return the registered client details
//        return ResponseEntity.ok(savedClient);
//    }
//
//    @PostMapping("/save")
//    public String saveRegisteredClient() {
//        DynamicClientRegistrationRepository dynamicClientRegistrationRepository = new DynamicClientRegistrationRepository();
//        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("oidc-client")
//                .clientSecret("{noop}secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .scopes(strings -> strings.addAll(List.of("read","write","openid")))
//                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(15)).accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build()).build();
//
//        dynamicClientRegistrationRepository.save(oidcClient);
//        return "sucess";
//    }
//
//    @GetMapping("/{clientId}")
//    public ResponseEntity<Client> getClient(@PathVariable String clientId) {
//        return clientRepository.findByClientId(clientId)
//                .map(ResponseEntity::ok)
//                .orElse(ResponseEntity.notFound().build());
//    }

    @GetMapping()
    public String greet(){
        return "hello";
    }

//    @PostMapping()
//    public String greet1(){
//        return "hello";
//    }

    @PostMapping
    public String registerClient(@RequestBody Client clientRequest) {
        // Map Client to RegisteredClient
//        Client registeredClient  =  Client.builder()
//                .id(UUID.randomUUID().toString())
//                .clientId(clientRequest.getClientId())
//                .clientIdIssuedAt(clientRequest.getClientIdIssuedAt() != null? clientRequest.getClientSecretExpiresAt() : Instant.now())
//                .c
//                .clientSecretExpiresAt()
//                .build();
        Client registeredClient = Client.builder().id(UUID.randomUUID().toString())
                .clientId(clientRequest.getClientId())
                .clientIdIssuedAt(clientRequest.getClientIdIssuedAt() != null ? clientRequest.getClientIdIssuedAt() : Instant.now())
                .clientSecret(clientRequest.getClientSecret())
                .clientSecretExpiresAt(clientRequest.getClientSecretExpiresAt())
                .clientName(clientRequest.getClientName())
                .clientAuthenticationMethods(clientRequest.getClientAuthenticationMethods())
                .authorizationGrantTypes(clientRequest.getAuthorizationGrantTypes())
                .redirectUris(clientRequest.getRedirectUris())
                .postLogoutRedirectUris(clientRequest.getPostLogoutRedirectUris())
                .scopes(clientRequest.getScopes())
                .build();

        // Save the RegisteredClient
        clientRepository.save(registeredClient);

        return "Client registered successfully with ID: " + registeredClient.getId();
    }



}

