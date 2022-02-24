package com.signal.api.client.models;

import javax.persistence.Id;

import org.springframework.data.mongodb.core.mapping.Document;

import com.signal.api.model.ERole;

@Document(collection = "roles")
public class Role {
	@Id
	private String id;

	private ERole name;

	public Role() {

	}

	public Role(ERole name) {
	    this.name = name;
	}

	public String getId() {
	    return id;
	}

	public void setId(String id) {
	    this.id = id;
	}

	public ERole getName() {
	    return name;
	}

	public void setName(ERole name) {
	    this.name = name;
	}
}
