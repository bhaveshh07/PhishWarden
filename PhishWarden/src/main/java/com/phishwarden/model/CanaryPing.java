package com.phishwarden.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "canary_pings")
public class CanaryPing {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String canaryToken;
    private String attackerIp;

    @Column(columnDefinition = "TEXT")
    private String attackerUserAgent;

    private String geoCountry;
    private String geoCity;

    @Enumerated(EnumType.STRING)
    private PingType pingType = PingType.FILE_OPEN;

    private LocalDateTime triggeredAt = LocalDateTime.now();

    public enum PingType { FILE_OPEN, FILE_ENCRYPT_ATTEMPT, EXFIL_ATTEMPT }

    public CanaryPing() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getCanaryToken() { return canaryToken; }
    public void setCanaryToken(String canaryToken) { this.canaryToken = canaryToken; }

    public String getAttackerIp() { return attackerIp; }
    public void setAttackerIp(String attackerIp) { this.attackerIp = attackerIp; }

    public String getAttackerUserAgent() { return attackerUserAgent; }
    public void setAttackerUserAgent(String attackerUserAgent) { this.attackerUserAgent = attackerUserAgent; }

    public String getGeoCountry() { return geoCountry; }
    public void setGeoCountry(String geoCountry) { this.geoCountry = geoCountry; }

    public String getGeoCity() { return geoCity; }
    public void setGeoCity(String geoCity) { this.geoCity = geoCity; }

    public PingType getPingType() { return pingType; }
    public void setPingType(PingType pingType) { this.pingType = pingType; }

    public LocalDateTime getTriggeredAt() { return triggeredAt; }
    public void setTriggeredAt(LocalDateTime triggeredAt) { this.triggeredAt = triggeredAt; }
}