package com.phishwarden.repository;

import com.phishwarden.model.ThreatEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ThreatEventRepository extends JpaRepository<ThreatEvent, Long> {

    List<ThreatEvent> findAllByOrderByOccurredAtDesc();

    List<ThreatEvent> findByIsResolvedFalseOrderByOccurredAtDesc();

    // ── Threat score queries ───────────────────────────────────────

    @Query("SELECT COUNT(t) FROM ThreatEvent t WHERE t.attackerIp = :ip AND t.eventType = :type")
    long countByAttackerIpAndEventType(@Param("ip") String ip,
                                       @Param("type") ThreatEvent.EventType type);

    @Query("SELECT COUNT(t) FROM ThreatEvent t WHERE t.attackerIp = :ip AND t.severity = :severity")
    long countByAttackerIpAndSeverity(@Param("ip") String ip,
                                      @Param("severity") ThreatEvent.Severity severity);

    @Query("SELECT DISTINCT t.attackerIp FROM ThreatEvent t WHERE t.attackerIp IS NOT NULL")
    List<String> findDistinctAttackerIps();

    // ── Timeline query — all events for one IP ordered by time ────
    @Query("SELECT t FROM ThreatEvent t WHERE t.attackerIp = :ip ORDER BY t.occurredAt ASC")
    List<ThreatEvent> findByAttackerIpOrderByOccurredAtAsc(@Param("ip") String ip);
}