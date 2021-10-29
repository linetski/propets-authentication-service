package com.spring.jwt.mongodb.password;

import java.util.Calendar;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
//import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.spring.jwt.mongodb.controllers.AuthController;
import com.spring.jwt.mongodb.models.PasswordResetToken;
import com.spring.jwt.mongodb.models.User;
import com.spring.jwt.mongodb.repository.PasswordTokenRepository;
import com.spring.jwt.mongodb.repository.UserRepository;

import propets.model.Email;

@Component
public class PasswordResetService {
	
	private static final String EMAIL_TOPIC = "email";
	
	private static final Logger logger = LoggerFactory.getLogger(PasswordResetService.class);
	
	@Autowired
	PasswordTokenRepository passwordTokenRepository;

	@Autowired
	UserRepository userRepository;
	
	@Autowired
	PasswordEncoder encoder;
	
	@Autowired
	private AmqpTemplate rabbitTemplate;
	
	@Value("${rabbitmq.exchange}")
	private String exchange;
	
	@Value("${rabbitmq.routingkey}")
	private String routingkey;
	//@Autowired
    //private KafkaTemplate<String, Email> emailKafkaTemplate;
	
	public void sendEmail(String token, User user) {
		String url = "http://localhost:3000" + "/reset_password?token=" + token;
		StringBuilder builder = new StringBuilder();
		builder.append("Hello!\r\n"
				+ "Forgot password?\r\n"
				+ "Click the link and enter a new password: \r\n");
		builder.append(url);
		builder.append("\r\n\r\n"
				+ "Best regards, site \"ProPets\"");
		builder.append("\n\n\n___\n"
				+ "This is an automatic letter.\n"
				+ "Please, don't answer.");
		Email email = new Email();
		email.setBody(builder.toString());
		email.setEmailAdress(user.getEmail());
		email.setSubject("reset password url:");
		logger.info("email to send: "+user.getEmail());
		//emailKafkaTemplate.send(EMAIL_TOPIC,email);
		rabbitTemplate.convertAndSend(exchange, routingkey, email);
	}
	
	public void createPasswordResetTokenForUser(User user, String token) {
	    PasswordResetToken myToken = new PasswordResetToken(token, user);
	    passwordTokenRepository.save(myToken);
	}
	
	public String validatePasswordResetToken(String token) {
	    final PasswordResetToken passToken = passwordTokenRepository.findByToken(token).orElse(null);
	    return !isTokenFound(passToken) ? "invalidToken" : null;
		/*
		 * return !isTokenFound(passToken) ? "invalidToken" : isTokenExpired(passToken)
		 * ? "expired" : null;
		 */
	}
	
	private boolean isTokenFound(PasswordResetToken passToken) {
	    return passToken != null;
	}

	private boolean isTokenExpired(PasswordResetToken passToken) {
	    final Calendar cal = Calendar.getInstance();
	    return passToken.getExpiryDate().before(cal.getTime());
	}

	
	public void changePassword(String token, String newPassword) {
		Optional<PasswordResetToken> passwordResetToken = passwordTokenRepository.findByToken(token);
		User user = passwordResetToken.get().getUser();
		user.setPassword(encoder.encode(newPassword));
		userRepository.save(user);
	}
}
