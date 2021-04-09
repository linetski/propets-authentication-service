package com.spring.jwt.mongodb.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.spring.jwt.mongodb.models.PasswordResetToken;


public interface PasswordTokenRepository extends MongoRepository<PasswordResetToken, String>{

	Optional<PasswordResetToken> findByToken(String token);
}
