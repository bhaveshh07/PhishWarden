package com.phishwarden.service;

import com.phishwarden.model.ThreatEvent;
import com.phishwarden.repository.ThreatEventRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AlertService {

    @Autowired
    private ThreatEventRepository threatRepo;

    public ThreatEvent fireThreatEvent(ThreatEvent.EventType type,
                                       ThreatEvent.Severity severity,
                                       String attackerIp,
                                       String details) {
        ThreatEvent event = new ThreatEvent();
        event.setEventType(type);
        event.setSeverity(severity);
        event.setAttackerIp(attackerIp);
        event.setDescription(details);   // ← was "description" (wrong variable name)

        ThreatEvent saved = threatRepo.save(event);

        System.out.printf("[PHISHWARDEN ALERT] %s | %s | IP: %s | %s%n",
                severity, type, attackerIp, details);

        return saved;
    }

    public List<ThreatEvent> getUnresolved() {
        return threatRepo.findByIsResolvedFalseOrderByOccurredAtDesc();
    }

    public List<ThreatEvent> getAll() {
        return threatRepo.findAllByOrderByOccurredAtDesc();
    }

    public long getUnresolvedCount() {
        // ← was countByIsResolvedFalse() which doesn't exist; use list size instead
        return threatRepo.findByIsResolvedFalseOrderByOccurredAtDesc().size();
    }

    public void resolve(Long eventId) {
        threatRepo.findById(eventId).ifPresent(e -> {
            e.setResolved(true);
            threatRepo.save(e);
        });
    }
}