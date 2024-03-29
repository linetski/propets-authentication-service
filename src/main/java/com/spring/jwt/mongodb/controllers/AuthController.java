package com.spring.jwt.mongodb.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.spring.jwt.mongodb.models.ERole;
import com.spring.jwt.mongodb.models.NewPasswordWithToken;
import com.spring.jwt.mongodb.models.Role;
import com.spring.jwt.mongodb.models.User;
import com.spring.jwt.mongodb.password.PasswordResetService;
import com.spring.jwt.mongodb.payload.request.LoginRequest;
import com.spring.jwt.mongodb.payload.request.SignupRequest;
import com.spring.jwt.mongodb.payload.response.JwtResponse;
import com.spring.jwt.mongodb.payload.response.MessageResponse;
import com.spring.jwt.mongodb.repository.RoleRepository;
import com.spring.jwt.mongodb.repository.UserRepository;
import com.spring.jwt.mongodb.security.jwt.JwtUtils;
import com.spring.jwt.mongodb.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	
	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
	
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;
	
	@Autowired
	PasswordResetService passwordResetService;
	
	
	@RequestMapping("/authenticate")
    public ResponseEntity<String> authenticate(@RequestHeader("Authorization") String authorizationToken) {
		logger.info("authenticate called with token: " + authorizationToken);
		String token = null;
		if (StringUtils.hasText(authorizationToken) && authorizationToken.startsWith("Bearer ")) {
			token = authorizationToken.substring(7, authorizationToken.length());
		}
		if(jwtUtils.validateJwtToken(token)) {
			return ResponseEntity.ok(jwtUtils.getUserNameFromJwtAuthorization(authorizationToken));
		} else
        return new ResponseEntity<String>("no or invalid token", HttpStatus.UNAUTHORIZED);
    }

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUserEmail(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);
		
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();		
		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());

		return ResponseEntity.ok(new JwtResponse(jwt, 
												 userDetails.getId(), 
												 userDetails.getUsername(), 
												 userDetails.getEmail(), 
												 roles));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerAndAuthenticateUser(@Valid @RequestBody SignupRequest signUpRequest) {
		/*
		 * if (userRepository.existsByUsername(signUpRequest.getUsername())) { return
		 * ResponseEntity .badRequest() .body(new
		 * MessageResponse("Error: Username is already taken!")); }
		 */

		if (userRepository.existsByEmail(signUpRequest.getUserEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Email is already in use!"));
		}

		// Create new user's account
		User user = new User(signUpRequest.getUsername(), 
							 signUpRequest.getUserEmail(),
							 encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRoles();
		Set<Role> roles = new HashSet<>();
		if (strRoles == null) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(adminRole);

					break;
				case "mod":
					Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(modRole);

					break;
				default:
					Role userRole = roleRepository.findByName(ERole.ROLE_USER)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		userRepository.save(user);
		
		LoginRequest loginRequest = new LoginRequest();
		loginRequest.setUserEmail(signUpRequest.getUserEmail());
		loginRequest.setPassword(signUpRequest.getPassword());
		return authenticateUser(loginRequest);
	}
	
	@RequestMapping("/getProfileName")
    public ResponseEntity<?> getProfileName(@RequestHeader (name="Authorization") String token) {		
		return ResponseEntity.ok(userRepository.findByEmail((jwtUtils.getUserNameFromJwtAuthorization(token))).get().getUsername());
    }
	
	@RequestMapping("/user/resetPassword")
	public ResponseEntity<?> resetPassword(HttpServletRequest request, @RequestBody String userEmail) {
	    Optional<User> user = userRepository.findByEmail(userEmail);
	    if (user == null) {
	        try {
				throw new Exception();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    }
	    String token = UUID.randomUUID().toString();
	    passwordResetService.createPasswordResetTokenForUser(user.get(), token);
	    passwordResetService.sendEmail(token, user.get());
	    return ResponseEntity.ok("email sended successfuly");
	}
	
	
	@RequestMapping("/user/changePassword")
	public ResponseEntity<?> saveNewPassword(@RequestBody NewPasswordWithToken newPasswordWithToken) {
		String badTokenReason = passwordResetService.validatePasswordResetToken(newPasswordWithToken.getToken());
		if (badTokenReason != null) {
			return ResponseEntity.ok(badTokenReason);
		} else {
			passwordResetService.changePassword(newPasswordWithToken.getToken(),newPasswordWithToken.getNewPassword());
		    return ResponseEntity.ok("Password changed succesfully");
		}
	}
}
