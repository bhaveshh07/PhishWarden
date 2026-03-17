package com.phishwarden.service;

import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class BlockedIpService {

    // IP → time it was blocked (permanent until manually unblocked)
    private final Map<String, LocalDateTime> blockedIps = new ConcurrentHashMap<>();

    public void blockIp(String ip) {
        blockedIps.put(ip, LocalDateTime.now());
        System.out.println("[PhishWarden] IP BLOCKED: " + ip);
    }

    public void unblockIp(String ip) {
        blockedIps.remove(ip);
        System.out.println("[PhishWarden] IP UNBLOCKED: " + ip);
    }

    public boolean isBlocked(String ip) {
        return blockedIps.containsKey(ip);
    }

    public Set<String> getAllBlocked() {
        return blockedIps.keySet();
    }

    public Map<String, String> getAllBlockedWithTime() {
        return blockedIps.entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> e.getValue().toString()
                ));
    }
}