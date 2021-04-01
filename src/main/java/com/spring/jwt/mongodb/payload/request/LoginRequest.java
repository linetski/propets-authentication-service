package com.spring.jwt.mongodb.payload.request;

import javax.validation.constraints.NotBlank;

public class LoginRequest {
	
	@NotBlank
	private String userEmail;

	public String getUserEmail() {
		return userEmail;
	}

	public void setUserEmail(String userEmail) {
		this.userEmail = userEmail;
	}

	@NotBlank
	private String password;


	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
