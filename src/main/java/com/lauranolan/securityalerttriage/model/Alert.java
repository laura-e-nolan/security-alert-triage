package com.lauranolan.securityalerttriage.model;

import java.time.LocalDateTime;
import java.util.Set;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import java.util.UUID;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Column;

@Entity
public class Alert {

    @Id
    private UUID id;

    @Column(name = "username")
    private String user;

    @Enumerated(EnumType.STRING)
    private AlertType alertType;
    private String reason;
    private LocalDateTime timestamp;

    @ElementCollection
    private Set<String> sourceIps;

    @ElementCollection
    private Set<String> devices;

    @Enumerated(EnumType.STRING)
    private AlertSeverity alertSeverity;

    protected Alert() {
    }
    public Alert(
            String user,
            AlertType alertType,
            String reason,
            LocalDateTime timestamp,
            Set<String> sourceIp,
            Set<String> device,
            AlertSeverity alertSeverity
    )

    {
        this.id = UUID.randomUUID();
        this.user = user;
        this.alertType = alertType;
        this.reason = reason;
        this.timestamp = timestamp;
        this.sourceIps = sourceIp;
        this.devices = device;
        this.alertSeverity = alertSeverity;
    }

    public UUID getId(){
        return id;
    }

    public String getUser() {
        return user;
    }

    public AlertType getAlertType() {
        return alertType;
    }

    public String getReason() {
        return reason;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public Set<String> getSourceIps(){
        return sourceIps;
    }

    public Set<String> getDevices(){
        return devices;
    }
    public AlertSeverity getAlertSeverity(){
        return alertSeverity;
    }
}
