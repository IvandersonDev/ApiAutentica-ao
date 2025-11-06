package com.example.msauthentication.service;

import com.example.msauthentication.model.User;
import com.example.msauthentication.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Service
@Transactional
public class AuthService {

    private final UserRepository userRepository;

    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public boolean emailExists(String email) {
        return userRepository.findByEmailIgnoreCase(email).isPresent();
    }

    public User registerUser(String name, String email, String password) {
        User user = new User();
        user.setFullName(name);
        user.setUsername(name);
        user.setEmail(email);
        user.setPassword(password);
        user.setLoggedIn(false);
        return userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmailIgnoreCase(email);
    }

    public User markLoggedIn(User user, boolean loggedIn) {
        user.setLoggedIn(loggedIn);
        user.setUpdatedAt(Instant.now());
        return userRepository.save(user);
    }

    public User updatePassword(User user, String newPassword) {
        user.setPassword(newPassword);
        user.setUpdatedAt(Instant.now());
        return userRepository.save(user);
    }
}
