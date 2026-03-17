package com.phishwarden.controller;

import com.phishwarden.model.User;
import com.phishwarden.repository.UserRepository;
import com.phishwarden.service.AuthService;
import com.phishwarden.service.MfaService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = {"http://localhost:5500", "http://127.0.0.1:5500"})
public class MfaController {

    @Autowired private MfaService mfaService;
    @Autowired private UserRepository userRepo;
    @Autowired private AuthService authService;

    @PostMapping("/verify-mfa")
    public ResponseEntity<?> verifyMfa(@RequestBody Map<String, String> body,
                                       HttpServletRequest req) {

        String sessionToken = body.getOrDefault("sessionToken", "").trim();
        String otp          = body.getOrDefault("otp", "").trim();

        if (sessionToken.isBlank() || otp.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Session token and code are required."));
        }

        String ip = req.getHeader("X-Forwarded-For") != null
                ? req.getHeader("X-Forwarded-For").split(",")[0].trim()
                : req.getRemoteAddr();
        String ua = req.getHeader("User-Agent");

        String email = mfaService.verifyOtp(sessionToken, otp, ip);

        if ("BLOCKED".equals(email)) {
            return ResponseEntity.status(403).body(Map.of(
                "error", "Too many wrong attempts. Your IP has been blocked by security.",
                "blocked", true
            ));
        }

        if (email == null) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", "Invalid or expired code. Please try again."));
        }

        Optional<User> userOpt = userRepo.findByEmail(email.toLowerCase());
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(401).body(Map.of("error", "User not found."));
        }

        AuthService.LoginResult result = authService.issueJwtForVerifiedUser(
                userOpt.get(), ip, ua);

        return ResponseEntity.ok(Map.of(
                "token",   result.getToken(),
                "name",    result.getName(),
                "role",    result.getRole(),
                "message", result.getMessage()
        ));
    }
}