package com.lauranolan.securityalerttriage.model;

import java.time.LocalDateTime;
import java.util.UUID;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Column;
import jakarta.persistence.Table;
import jakarta.persistence.Index;

@Entity
@Table(
        name = "security_event",
        indexes = {
                @Index(
                        name = "idx_security_event_detection",
                        columnList = "username, event_type, outcome, timestamp"
                )
        }
)

public class SecurityEvent {
    @Column(name = "username")
    private String user;
    private String sourceIp;
    private String device;
    private String resource;


    @Enumerated(EnumType.STRING)
    private EventType eventType;

    @Enumerated(EnumType.STRING)
    private EventOutcome outcome;

    private LocalDateTime timestamp;

    @Id
    private UUID id;

    protected SecurityEvent() {
    }


    public SecurityEvent(
            LocalDateTime timestamp,
            String user,
            EventType eventType,
            String sourceIp,
            String device,
            String resource,
            EventOutcome outcome
    ) {
        this.id = UUID.randomUUID();
        this.timestamp = timestamp;
        this.user = user;
        this.sourceIp = sourceIp;
        this.device = device;
        this.resource = resource;
        this.eventType = eventType;
        this.outcome = outcome;
    }
        public EventType getEventType() {
            return eventType;
        }
        public EventOutcome getOutcome(){
            return outcome;
        }
        public String getUser(){
            return user;
    }
        public String getSourceIp(){
            return sourceIp;
        }
        public String getDevice(){
            return device;
    }
        public String getResource(){
            return resource;
        }
        public LocalDateTime getTimestamp(){
            return timestamp;
        }
        public UUID getId(){
            return id;
        }

}
