package com.lauranolan.securityalerttriage.model;

import java.time.LocalDateTime;

public class Alert {
    private String user;
    private AlertType alertType;
    private String reason;
    private LocalDateTime timestamp;

    public Alert(
            String user,
            AlertType alertType,
            String reason,
            LocalDateTime timestamp
    ) {
        this.user = user;
        this.alertType = alertType;
        this.reason = reason;
        this.timestamp = timestamp;
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
}
