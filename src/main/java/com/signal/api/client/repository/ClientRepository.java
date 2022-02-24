package com.signal.api.client.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.signal.api.client.models.Client;

public interface ClientRepository extends MongoRepository<Client, String>{
	Optional<Client> findByUsername(String username);
	Boolean existsByUsername(String username);
	Boolean existsByEmail(String email);
}
