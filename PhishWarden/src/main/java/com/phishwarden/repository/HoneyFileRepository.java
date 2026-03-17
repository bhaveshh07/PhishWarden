package com.phishwarden.repository;

import com.phishwarden.model.HoneyFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface HoneyFileRepository extends JpaRepository<HoneyFile, Long> {
    Optional<HoneyFile> findByCanaryToken(String canaryToken);
    List<HoneyFile> findAllByOrderByCreatedAtDesc();
}