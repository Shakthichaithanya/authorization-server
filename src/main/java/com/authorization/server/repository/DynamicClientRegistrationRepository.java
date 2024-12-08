package com.authorization.server.repository;

import com.authorization.server.model.Client;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;


public class DynamicClientRegistrationRepository implements RegisteredClientRepository{


    @Autowired
    private  ClientRepository clientRepository;

    public DynamicClientRegistrationRepository() {

    }


    @Override
    public void save(RegisteredClient registeredClient) {
        //used dynamic client registration no need to write logic here
    }

    @Override
    public RegisteredClient findById(String id) {
        return clientRepository.findById(id)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId)
                .map(this::toRegisteredClient).orElse(null);
    }

    private RegisteredClient toRegisteredClient(Client client) {
        return RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientIdIssuedAt(client.getClientIdIssuedAt())
                .clientSecret(client.getClientSecret())
                .clientSecretExpiresAt(client.getClientSecretExpiresAt())
                .clientName(client.getClientName())

                .clientAuthenticationMethods(methods -> methods.addAll(client.getClientAuthenticationMethods().stream()
                        .map(ClientAuthenticationMethod::new)
                        .toList()))
                .authorizationGrantTypes(grants -> grants.addAll(client.getAuthorizationGrantTypes().stream()
                        .map(AuthorizationGrantType::new)
                        .toList()))
                .redirectUris(uris -> uris.addAll(client.getRedirectUris()))
                .postLogoutRedirectUris(uris -> uris.addAll(client.getPostLogoutRedirectUris()))
                .scopes(scopes -> scopes.addAll(client.getScopes()))
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(15)).accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).idTokenSignatureAlgorithm(SignatureAlgorithm.ES256).refreshTokenTimeToLive(Duration.ofMinutes(30)).build())
                .build();
    }
}
