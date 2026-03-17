package com.phishwarden.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "login_attempts")
public class LoginAttempt {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String emailUsed;
    private String ipAddress;

    @Column(columnDefinition = "TEXT")
    private String userAgent;

    @Enumerated(EnumType.STRING)
    private AttemptType attemptType = AttemptType.UNKNOWN;

    private boolean wasSuccessful = false;

    private LocalDateTime attemptedAt = LocalDateTime.now();

    public enum AttemptType { REAL_USER, HONEYTOKEN_HIT, BRUTE_FORCE, UNKNOWN }

    public LoginAttempt() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getEmailUsed() { return emailUsed; }
    public void setEmailUsed(String emailUsed) { this.emailUsed = emailUsed; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

    public AttemptType getAttemptType() { return attemptType; }
    public void setAttemptType(AttemptType attemptType) { this.attemptType = attemptType; }

    public boolean isWasSuccessful() { return wasSuccessful; }
    public void setWasSuccessful(boolean wasSuccessful) { this.wasSuccessful = wasSuccessful; }

    public LocalDateTime getAttemptedAt() { return attemptedAt; }
    public void setAttemptedAt(LocalDateTime attemptedAt) { this.attemptedAt = attemptedAt; }
}