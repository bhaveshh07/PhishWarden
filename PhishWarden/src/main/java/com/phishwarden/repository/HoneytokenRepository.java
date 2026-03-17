package com.phishwarden.repository;

import com.phishwarden.model.Honeytoken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface HoneytokenRepository extends JpaRepository<Honeytoken, Long> {
    Optional<Honeytoken> findByFakeEmail(String fakeEmail);
    boolean existsByFakeEmail(String fakeEmail);
    List<Honeytoken> findByIsTriggeredTrue();
}