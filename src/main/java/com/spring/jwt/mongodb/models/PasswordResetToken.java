package com.spring.jwt.mongodb.models;

import java.util.Date;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "PasswordResetToken")
public class PasswordResetToken {
 
    private static final int EXPIRATION = 60 * 24;
 
    @Id
    private String id;
 
    private String token;
 
    @DBRef
    private User user;
 
    private Date expiryDate;
    
    public PasswordResetToken(String token, User user) {
    	this.token = token;
    	this.user = user;
    }

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	public Date getExpiryDate() {
		return expiryDate;
	}

	public void setExpiryDate(Date expiryDate) {
		this.expiryDate = expiryDate;
	}
}