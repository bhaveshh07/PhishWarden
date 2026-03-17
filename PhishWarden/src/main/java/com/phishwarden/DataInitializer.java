package com.phishwarden;

import com.phishwarden.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Runs once on startup.
 * Sets correct BCrypt-hashed passwords for all test users.
 * Safe to run multiple times — checks before updating.
 */
@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepo;

    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);

    @Override
    public void run(String... args) {
        setPassword("alice@smallbiz.com", "Password123");
        setPassword("bob@smallbiz.com",   "Password123");
        setPassword("carol@smallbiz.com", "Password123");
        System.out.println("[PhishWarden] Test user passwords initialised.");
    }

    private void setPassword(String email, String rawPassword) {
        userRepo.findByEmail(email).ifPresent(user -> {
            user.setPasswordHash(bcrypt.encode(rawPassword));
            userRepo.save(user);
        });
    }
}