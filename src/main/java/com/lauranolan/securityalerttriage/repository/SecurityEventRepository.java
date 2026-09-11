package com.lauranolan.securityalerttriage.repository;

import com.lauranolan.securityalerttriage.model.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import com.lauranolan.securityalerttriage.model.EventType;
import com.lauranolan.securityalerttriage.model.EventOutcome;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.List;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, UUID> {


    List<SecurityEvent> findByUserAndEventTypeAndOutcomeAndTimestampBetween(
            String user,
            EventType eventType,
            EventOutcome eventOutcome,
            LocalDateTime start,
            LocalDateTime end
    );
}
