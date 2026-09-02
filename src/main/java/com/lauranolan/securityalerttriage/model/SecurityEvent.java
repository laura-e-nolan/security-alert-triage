package com.lauranolan.securityalerttriage.model;

import java.time.LocalDateTime;
import java.util.UUID;

public class SecurityEvent {
    private String user;
    private String sourceIp;
    private String device;
    private String resource;
    private EventType eventType;
    private EventOutcome outcome;
    private LocalDateTime timestamp;
    private UUID id;

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
