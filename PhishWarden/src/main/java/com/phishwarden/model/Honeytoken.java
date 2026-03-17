package com.phishwarden.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "honeytokens")
public class Honeytoken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String fakeEmail;

    private String fakePassword;

    @Column(unique = true)
    private String tokenUid;

    private boolean isTriggered = false;

    private LocalDateTime createdAt = LocalDateTime.now();

    public Honeytoken() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getFakeEmail() { return fakeEmail; }
    public void setFakeEmail(String fakeEmail) { this.fakeEmail = fakeEmail; }

    public String getFakePassword() { return fakePassword; }
    public void setFakePassword(String fakePassword) { this.fakePassword = fakePassword; }

    public String getTokenUid() { return tokenUid; }
    public void setTokenUid(String tokenUid) { this.tokenUid = tokenUid; }

    public boolean isTriggered() { return isTriggered; }
    public void setTriggered(boolean triggered) { isTriggered = triggered; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}