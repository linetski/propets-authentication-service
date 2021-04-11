package com.spring.jwt.mongodb.password;

import java.util.Calendar;
import java.util.Locale;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import com.spring.jwt.mongodb.models.PasswordResetToken;
import com.spring.jwt.mongodb.models.User;
import com.spring.jwt.mongodb.repository.PasswordTokenRepository;
import com.spring.jwt.mongodb.repository.UserRepository;

@Component
public class PasswordResetService {
	
	@Autowired
	PasswordTokenRepository passwordTokenRepository;
	
	@Autowired
    JavaMailSender emailSender;

	@Autowired
	UserRepository userRepository;
	
	@Autowired
	PasswordEncoder encoder;
	
	public void sendEmail(String token, User user) {
		emailSender.send(constructResetTokenEmail("heroku", null, token, user));
	}

	private SimpleMailMessage constructResetTokenEmail(String contextPath, Locale locale, String token, User user) {
	    String url = "http://localhost:3000" + "/user/changePassword?token=" + token;
	    //String message = messages.getMessage("message.resetPassword", null, locale);
	    return constructEmail("reset password url:",  url, user);
	}

	private SimpleMailMessage constructEmail(String subject, String body, User user) {
	    SimpleMailMessage email = new SimpleMailMessage();
	    email.setSubject(subject);
	    email.setText(body);
	    email.setTo(user.getEmail());
	    return email;
	}
	
	public void createPasswordResetTokenForUser(User user, String token) {
	    PasswordResetToken myToken = new PasswordResetToken(token, user);
	    passwordTokenRepository.save(myToken);
	}
	
	public String validatePasswordResetToken(String token) {
	    final PasswordResetToken passToken = passwordTokenRepository.findByToken(token).orElse(null);

	    return !isTokenFound(passToken) ? "invalidToken"
	            : isTokenExpired(passToken) ? "expired"
	            : null;
	}
	
	private boolean isTokenFound(PasswordResetToken passToken) {
	    return passToken != null;
	}

	private boolean isTokenExpired(PasswordResetToken passToken) {
	    final Calendar cal = Calendar.getInstance();
	    return passToken.getExpiryDate().before(cal.getTime());
	}
	
	public JavaMailSender getEmailSender() {
		return emailSender;
	}

	public void setEmailSender(JavaMailSender emailSender) {
		this.emailSender = emailSender;
	}
	
	public void changePassword(String token, String newPassword) {
		Optional<PasswordResetToken> passwordResetToken = passwordTokenRepository.findByToken(token);
		User user = passwordResetToken.get().getUser();
		user.setPassword(encoder.encode(newPassword));
		userRepository.save(user);
	}
}
