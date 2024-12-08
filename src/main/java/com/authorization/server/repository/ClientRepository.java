package com.authorization.server.repository;

import com.authorization.server.model.Client;
import java.util.Optional;
import org.springframework.data.mongodb.repository.MongoRepository;


public interface ClientRepository extends MongoRepository<Client, String> {
    Optional<Client> findByClientId(String clientId);
}
