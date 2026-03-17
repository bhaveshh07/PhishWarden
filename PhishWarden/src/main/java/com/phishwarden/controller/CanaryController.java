package com.phishwarden.controller;

import com.phishwarden.model.CanaryPing;
import com.phishwarden.service.CanaryService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * CanaryController — /api/canary
 *
 * This endpoint is PUBLIC on purpose.
 * When an attacker opens a honey file, their machine calls back to
 * /api/canary/ping?token=XXX — revealing their real IP.
 * We return a 1x1 transparent GIF so it looks like a tracking pixel.
 */
@RestController
@RequestMapping("/api/canary")
@CrossOrigin(origins = "*")
public class CanaryController {

    @Autowired
    private CanaryService canaryService;

    // Attacker's machine hits this URL when honey file is opened
    @GetMapping("/ping")
    public ResponseEntity<byte[]> ping(
            @RequestParam String token,
            @RequestParam(defaultValue = "open") String t,
            HttpServletRequest req) {

        canaryService.handlePing(token, t, req);

        // Return a 1x1 transparent GIF — attacker's tool sees 200 OK, no suspicion
        byte[] transparentGif = {
            71, 73, 70, 56, 57, 97, 1, 0, 1, 0, -128, 0, 0, 0, 0, 0,
            -1, -1, -1, 33, -7, 4, 1, 0, 0, 0, 0, 44, 0, 0, 0, 0,
            1, 0, 1, 0, 0, 2, 2, 68, 1, 0, 59
        };
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("image/gif"))
                .body(transparentGif);
    }

    // SOC admin view — lists all canary pings received
    @GetMapping("/pings")
    public ResponseEntity<List<CanaryPing>> getAllPings() {
        return ResponseEntity.ok(canaryService.getAllPings());
    }
}
