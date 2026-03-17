package com.phishwarden.controller;

import com.phishwarden.model.CanaryPing;
import com.phishwarden.model.ThreatEvent;
import com.phishwarden.repository.CanaryPingRepository;
import com.phishwarden.repository.ThreatEventRepository;
import com.phishwarden.service.BlockedIpService;
import com.phishwarden.service.ThreatScoreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/soc")
@CrossOrigin(origins = "*")
public class SocController {

    @Autowired private ThreatEventRepository threatEventRepo;
    @Autowired private CanaryPingRepository  canaryPingRepo;
    @Autowired private ThreatScoreService    threatScoreService;
    @Autowired private BlockedIpService      blockedIpService;

    @GetMapping("/events")
    public ResponseEntity<?> getEvents(
            @RequestParam(defaultValue = "false") boolean unresolvedOnly) {
        List<ThreatEvent> events = unresolvedOnly
                ? threatEventRepo.findByIsResolvedFalseOrderByOccurredAtDesc()
                : threatEventRepo.findAllByOrderByOccurredAtDesc();
        return ResponseEntity.ok(events.stream().map(this::eventToMap).toList());
    }

    @PostMapping("/events/{id}/resolve")
    public ResponseEntity<?> resolve(@PathVariable Long id) {
        return threatEventRepo.findById(id).map(e -> {
            e.setResolved(true);
            threatEventRepo.save(e);
            return ResponseEntity.ok(Map.of("status", "resolved"));
        }).orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/canary-pings")
    public ResponseEntity<?> getCanaryPings() {
        return ResponseEntity.ok(
                canaryPingRepo.findAllByOrderByTriggeredAtDesc()
                              .stream().map(this::pingToMap).toList());
    }

    @GetMapping("/threat-scores")
    public ResponseEntity<?> getThreatScores() {
        return ResponseEntity.ok(threatScoreService.getAllScores());
    }

    @GetMapping("/threat-score/{ip}")
    public ResponseEntity<?> getThreatScore(@PathVariable String ip) {
        return ResponseEntity.ok(threatScoreService.calculateScore(ip));
    }

    @GetMapping("/timeline/{ip}")
    public ResponseEntity<?> getTimeline(@PathVariable String ip) {
        List<ThreatEvent> events =
                threatEventRepo.findByAttackerIpOrderByOccurredAtAsc(ip);
        List<Map<String, Object>> timeline = new ArrayList<>();
        for (ThreatEvent e : events) {
            Map<String, Object> step = new LinkedHashMap<>();
            step.put("time",     e.getOccurredAt().toString());
            step.put("type",     e.getEventType().name());
            step.put("severity", e.getSeverity().name());
            step.put("label",    friendlyLabel(e.getEventType()));
            step.put("desc",     e.getDescription());
            timeline.add(step);
        }
        return ResponseEntity.ok(Map.of("ip", ip, "steps", timeline));
    }

    // ── IP Block management ───────────────────────────────────────

    @PostMapping("/block-ip")
    public ResponseEntity<?> blockIp(@RequestBody Map<String, String> body) {
        String ip = body.getOrDefault("ip", "").trim();
        if (ip.isBlank()) return ResponseEntity.badRequest()
                .body(Map.of("error", "IP is required."));
        blockedIpService.blockIp(ip);
        return ResponseEntity.ok(Map.of(
                "status",  "blocked",
                "ip",      ip,
                "message", "IP " + ip + " has been blocked. All requests will be denied."
        ));
    }

    @PostMapping("/unblock-ip")
    public ResponseEntity<?> unblockIp(@RequestBody Map<String, String> body) {
        String ip = body.getOrDefault("ip", "").trim();
        if (ip.isBlank()) return ResponseEntity.badRequest()
                .body(Map.of("error", "IP is required."));
        blockedIpService.unblockIp(ip);
        return ResponseEntity.ok(Map.of("status", "unblocked", "ip", ip));
    }

    @GetMapping("/blocked-ips")
    public ResponseEntity<?> getBlockedIps() {
        return ResponseEntity.ok(Map.of(
                "blocked", blockedIpService.getAllBlockedWithTime()
        ));
    }

    // ── Helpers ───────────────────────────────────────────────────
    private Map<String, Object> eventToMap(ThreatEvent e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id",          e.getId());
        m.put("eventType",   e.getEventType().name());
        m.put("severity",    e.getSeverity().name());
        m.put("attackerIp",  e.getAttackerIp());
        m.put("description", e.getDescription());
        m.put("isResolved",  e.isResolved());
        m.put("occurredAt",  e.getOccurredAt().toString());
        return m;
    }

    private Map<String, Object> pingToMap(CanaryPing p) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id",          p.getId());
        m.put("canaryToken", p.getCanaryToken());
        m.put("attackerIp",  p.getAttackerIp());
        m.put("geoCity",     p.getGeoCity());
        m.put("geoCountry",  p.getGeoCountry());
        m.put("triggeredAt", p.getTriggeredAt().toString());
        return m;
    }

    private String friendlyLabel(ThreatEvent.EventType type) {
        return switch (type) {
            case HONEYTOKEN_LOGIN      -> "Honeytoken Triggered";
            case BRUTE_FORCE           -> "Brute Force Attack";
            case PHISHING_CRED_HARVEST -> "Suspicious Login";
            case CANARY_PING           -> "File Download";
            case PRIVILEGE_ESCALATION  -> "Privilege Escalation";
        };
    }
}