package com.lauranolan.securityalerttriage.model;

import java.util.Optional;

public class EventProcessingResult {

    private SecurityEvent event;
    private Optional<Alert> alert;

    public EventProcessingResult(SecurityEvent event, Optional<Alert> alert) {
        this.event = event;
        this.alert = alert;
    }

    public SecurityEvent getEvent() {
        return event;
    }

    public Optional<Alert> getAlert() {
        return alert;
    }
}
