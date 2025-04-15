package com.user_service.user_service.service;

import com.user_service.user_service.dto.AuthRequest;
import com.user_service.user_service.dto.AuthResponse;
import com.user_service.user_service.dto.RegisterRequest;
import com.user_service.user_service.model.User;
import com.user_service.user_service.repository.UserRepository;
import com.user_service.user_service.security.JwtTokenProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public String register(RegisterRequest request) {
        if(userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new RuntimeException("User is already registered");
        }
//        User user = User.builder()
//                .username(request.getUsername())
//                .password(request.getPassword())
//                .roles(Collections.singleton("Role_User"))
//                .build();
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRoles(Collections.singleton("Role_User"));
        userRepository.save(user);
        return "User Registered Successfully";
    }

    public AuthResponse login(AuthRequest request) {
        Optional<User> user = userRepository.findByUsername(request.getUsername());
        if(user.isPresent() && passwordEncoder.matches(request.getPassword(), user.get().getPassword())) {
            String token = jwtTokenProvider.generateToken(user.get().getUsername(), user.get().getRoles());
            return new AuthResponse(token);
        }
        throw new RuntimeException("Invalid Credentials");
    }

}
