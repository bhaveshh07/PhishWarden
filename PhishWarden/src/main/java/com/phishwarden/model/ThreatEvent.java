package com.phishwarden.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "threat_events")
public class ThreatEvent {

    public enum EventType {
        HONEYTOKEN_LOGIN,
        PHISHING_CRED_HARVEST,
        BRUTE_FORCE,
        CANARY_PING,
        PRIVILEGE_ESCALATION    // ← new
    }

    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type")
    private EventType eventType;

    @Enumerated(EnumType.STRING)
    private Severity severity;

    @Column(name = "attacker_ip")
    private String attackerIp;

    private String description;

    @Column(name = "is_resolved")
    private boolean isResolved = false;

    @Column(name = "occurred_at")
    private LocalDateTime occurredAt = LocalDateTime.now();

    // ── Getters & Setters ─────────────────────────────────────────
    public Long getId()                     { return id; }
    public void setId(Long id)              { this.id = id; }

    public EventType getEventType()              { return eventType; }
    public void setEventType(EventType eventType){ this.eventType = eventType; }

    public Severity getSeverity()                { return severity; }
    public void setSeverity(Severity severity)   { this.severity = severity; }

    public String getAttackerIp()                { return attackerIp; }
    public void setAttackerIp(String attackerIp) { this.attackerIp = attackerIp; }

    public String getDescription()               { return description; }
    public void setDescription(String desc)      { this.description = desc; }

    public boolean isResolved()                  { return isResolved; }
    public void setResolved(boolean resolved)    { this.isResolved = resolved; }

    public LocalDateTime getOccurredAt()              { return occurredAt; }
    public void setOccurredAt(LocalDateTime t)        { this.occurredAt = t; }
}