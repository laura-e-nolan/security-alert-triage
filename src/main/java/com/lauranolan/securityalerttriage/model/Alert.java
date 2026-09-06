package com.lauranolan.securityalerttriage.model;

import java.time.LocalDateTime;
import java.util.Set;

public class Alert {
    private String user;
    private AlertType alertType;
    private String reason;
    private LocalDateTime timestamp;
    private Set<String> sourceIps;
    private Set<String> devices;

    public Alert(
            String user,
            AlertType alertType,
            String reason,
            LocalDateTime timestamp,
            Set<String> sourceIp,
            Set<String> device
    ) {
        this.user = user;
        this.alertType = alertType;
        this.reason = reason;
        this.timestamp = timestamp;
        this.sourceIps = sourceIp;
        this.devices = device;
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
}
