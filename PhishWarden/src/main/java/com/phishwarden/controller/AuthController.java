package com.phishwarden.controller;

import com.phishwarden.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = {"http://localhost:5500", "http://127.0.0.1:5500"})
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body,
                                   HttpServletRequest req) {

        String email    = body.getOrDefault("email", "").trim().toLowerCase();
        String password = body.getOrDefault("password", "");

        if (email.isBlank() || password.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Email and password are required."));
        }

        AuthService.LoginResult result = authService.login(email, password, req);

        // Brute force lockout
        if (result.isBlocked()) {
            return ResponseEntity.status(429).body(Map.of(
                "error",          result.getMessage(),
                "lockoutSeconds", result.getLockoutSeconds()
            ));
        }

        // New device — MFA required
        if (result.isMfaRequired()) {
            return ResponseEntity.status(202).body(Map.of(
                "status",       "MFA_REQUIRED",
                "sessionToken", result.getSessionToken(),
                "message",      result.getMessage()
            ));
        }

        // Wrong credentials
        if (!result.isSuccess()) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", result.getMessage()));
        }

        // Full success — identical shape for real and honey sessions
        return ResponseEntity.ok(Map.of(
                "token",   result.getToken(),
                "name",    result.getName(),
                "role",    result.getRole(),
                "message", result.getMessage()
        ));
    }
}