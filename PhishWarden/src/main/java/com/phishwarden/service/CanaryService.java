package com.phishwarden.service;

import com.phishwarden.model.CanaryPing;
import com.phishwarden.model.ThreatEvent;
import com.phishwarden.repository.CanaryPingRepository;
import com.phishwarden.repository.HoneyFileRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CanaryService {

    @Autowired
    private CanaryPingRepository canaryPingRepo;

    @Autowired
    private HoneyFileRepository honeyFileRepo;

    @Autowired
    private AlertService alertService;

    /**
     * Called when an attacker's machine phones home after opening a honey file.
     * Logs the ping and fires a CRITICAL threat event.
     */
    public void handlePing(String canaryToken, String pingType, HttpServletRequest req) {
        String ip = getClientIp(req);
        String ua = req.getHeader("User-Agent");

        honeyFileRepo.findByCanaryToken(canaryToken).ifPresent(hf -> {

            CanaryPing ping = new CanaryPing();
            ping.setCanaryToken(canaryToken);
            ping.setAttackerIp(ip);
            ping.setAttackerUserAgent(ua);
            ping.setPingType(parsePingType(pingType));
            canaryPingRepo.save(ping);

            alertService.fireThreatEvent(
                    ThreatEvent.EventType.CANARY_PING,
                    ThreatEvent.Severity.CRITICAL,
                    ip,
                    String.format("Canary fired! File: %s | Token: %s | Action: %s | UA: %s",
                            hf.getFilename(), canaryToken, pingType, ua)
            );
        });
    }

    public List<CanaryPing> getAllPings() {
        return canaryPingRepo.findAllByOrderByTriggeredAtDesc();
    }

    private CanaryPing.PingType parsePingType(String t) {
        if (t == null) return CanaryPing.PingType.FILE_OPEN;
        return switch (t.toUpperCase()) {
            case "ENCRYPT" -> CanaryPing.PingType.FILE_ENCRYPT_ATTEMPT;
            case "EXFIL"   -> CanaryPing.PingType.EXFIL_ATTEMPT;
            default        -> CanaryPing.PingType.FILE_OPEN;
        };
    }

    private String getClientIp(HttpServletRequest req) {
        String xfh = req.getHeader("X-Forwarded-For");
        return (xfh != null && !xfh.isBlank())
                ? xfh.split(",")[0].trim()
                : req.getRemoteAddr();
    }
}