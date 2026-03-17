package com.phishwarden.controller;

import com.phishwarden.model.ThreatEvent;
import com.phishwarden.service.AlertService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/honey")
@CrossOrigin(origins = "*")
public class EscalationController {

    @Autowired private AlertService alertService;

    /**
     * Called when attacker clicks a privileged action inside the honey dashboard.
     * action: "reset_passwords" | "export_database" | "admin_controls" | "view_credentials"
     */
    @PostMapping("/escalation")
    public ResponseEntity<?> escalation(@RequestBody Map<String, String> body,
                                        HttpServletRequest req) {

        String action = body.getOrDefault("action", "unknown");
        String ip     = req.getHeader("X-Forwarded-For") != null
                ? req.getHeader("X-Forwarded-For").split(",")[0].trim()
                : req.getRemoteAddr();
        String ua     = req.getHeader("User-Agent");

        String description = switch (action) {
            case "reset_passwords"  -> "PRIVILEGE ESCALATION: Attacker attempted Reset All Passwords";
            case "export_database"  -> "PRIVILEGE ESCALATION: Attacker attempted Export Database";
            case "admin_controls"   -> "PRIVILEGE ESCALATION: Attacker accessed Admin Control Panel";
            case "view_credentials" -> "PRIVILEGE ESCALATION: Attacker accessed Employee Credentials dump";
            default                 -> "PRIVILEGE ESCALATION: Unknown admin action attempted";
        };

        alertService.fireThreatEvent(
                ThreatEvent.EventType.PRIVILEGE_ESCALATION,
                ThreatEvent.Severity.CRITICAL,
                ip,
                description + " | IP: " + ip + " | UA: " + ua
        );

        // Return fake "success" so attacker thinks it worked
        return ResponseEntity.ok(switch (action) {
            case "reset_passwords"  -> Map.of("status", "success", "message", "Password reset emails sent to 15 users.");
            case "export_database"  -> Map.of("status", "success", "message", "Export queued. File will be ready in 60 seconds.", "downloadUrl", "/api/honey/fake-export");
            case "admin_controls"   -> Map.of("status", "success", "message", "Admin session granted.");
            case "view_credentials" -> Map.of("status", "success", "message", "Loading credential vault...");
            default                 -> Map.of("status", "success", "message", "Action completed.");
        });
    }
}