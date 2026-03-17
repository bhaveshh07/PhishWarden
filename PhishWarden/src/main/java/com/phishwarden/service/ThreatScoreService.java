package com.phishwarden.service;

import com.phishwarden.model.ThreatEvent;
import com.phishwarden.repository.CanaryPingRepository;
import com.phishwarden.repository.LoginAttemptRepository;
import com.phishwarden.repository.ThreatEventRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class ThreatScoreService {

    @Autowired private ThreatEventRepository threatEventRepo;
    @Autowired private LoginAttemptRepository loginAttemptRepo;
    @Autowired private CanaryPingRepository canaryPingRepo;

    // ─────────────────────────────────────────────────────────────
    // Calculate threat score for a specific IP
    // ─────────────────────────────────────────────────────────────
    public Map<String, Object> calculateScore(String ip) {
        int score = 0;
        Map<String, Integer> breakdown = new LinkedHashMap<>();

        // Honeytoken login → +50 per hit
        long honeytokenHits = threatEventRepo.countByAttackerIpAndEventType(
                ip, ThreatEvent.EventType.HONEYTOKEN_LOGIN);
        if (honeytokenHits > 0) {
            int pts = (int) (honeytokenHits * 50);
            score += pts;
            breakdown.put("Honeytoken triggered ×" + honeytokenHits, pts);
        }

        // Brute force attempts → +20
        long bruteForceEvents = threatEventRepo.countByAttackerIpAndEventType(
                ip, ThreatEvent.EventType.BRUTE_FORCE);
        if (bruteForceEvents > 0) {
            int pts = (int) (bruteForceEvents * 20);
            score += pts;
            breakdown.put("Brute force detected ×" + bruteForceEvents, pts);
        }

        // Canary file access → +20 per file
        long canaryPings = canaryPingRepo.countByAttackerIp(ip);
        if (canaryPings > 0) {
            int pts = (int) (canaryPings * 20);
            score += pts;
            breakdown.put("Honey file accessed ×" + canaryPings, pts);
        }

        // Failed login attempts → +5 each (up to 30)
        long failedLogins = loginAttemptRepo.countFailedLoginsForIp(ip);
        if (failedLogins > 0) {
            int pts = (int) Math.min(failedLogins * 5, 30);
            score += pts;
            breakdown.put("Failed logins ×" + failedLogins, pts);
        }

        // Odd hour logins → +10
        long oddHourEvents = threatEventRepo.countByAttackerIpAndSeverity(
                ip, ThreatEvent.Severity.MEDIUM);
        if (oddHourEvents > 0) {
            int pts = (int) Math.min(oddHourEvents * 10, 20);
            score += pts;
            breakdown.put("Unusual hour activity ×" + oddHourEvents, pts);
        }

        // Privilege escalation attempts → +40
        long escalationEvents = threatEventRepo.countByAttackerIpAndEventType(
                ip, ThreatEvent.EventType.PRIVILEGE_ESCALATION);
        if (escalationEvents > 0) {
            int pts = (int) (escalationEvents * 40);
            score += pts;
            breakdown.put("Privilege escalation ×" + escalationEvents, pts);
        }

        // Cap at 100
        score = Math.min(score, 100);

        return Map.of(
                "ip",        ip,
                "score",     score,
                "label",     getLabel(score),
                "level",     getLevel(score),
                "breakdown", breakdown
        );
    }

    // ─────────────────────────────────────────────────────────────
    // Get scores for ALL known attacker IPs
    // ─────────────────────────────────────────────────────────────
    public List<Map<String, Object>> getAllScores() {
        List<String> ips = threatEventRepo.findDistinctAttackerIps();
        return ips.stream()
                .map(this::calculateScore)
                .sorted((a, b) -> (int) b.get("score") - (int) a.get("score"))  // highest first
                .toList();
    }

    private String getLabel(int score) {
        if (score >= 90) return "Active Intrusion Detected";
        if (score >= 70) return "High Threat — Immediate Action Required";
        if (score >= 40) return "Suspicious Activity";
        if (score >= 20) return "Low Risk — Monitor";
        return "No Threat Detected";
    }

    private String getLevel(int score) {
        if (score >= 90) return "CRITICAL";
        if (score >= 70) return "HIGH";
        if (score >= 40) return "MEDIUM";
        if (score >= 20) return "LOW";
        return "NONE";
    }
}