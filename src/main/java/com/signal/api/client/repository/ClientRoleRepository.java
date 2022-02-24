package com.signal.api.client.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.signal.api.model.ERole;
import com.signal.api.client.models.Role;

public interface ClientRoleRepository extends MongoRepository<Role, String>{
	Optional<Role> findByName(ERole name);
}
