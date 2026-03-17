package com.phishwarden.repository;

import com.phishwarden.model.CanaryPing;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface CanaryPingRepository extends JpaRepository<CanaryPing, Long> {

    List<CanaryPing> findAllByOrderByTriggeredAtDesc();

    @Query("SELECT COUNT(c) FROM CanaryPing c WHERE c.attackerIp = :ip")
    long countByAttackerIp(@Param("ip") String ip);
}