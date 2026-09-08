package com.lauranolan.securityalerttriage.service;

import com.lauranolan.securityalerttriage.detection.DetectionEngine;
import com.lauranolan.securityalerttriage.model.SecurityEvent;
import com.lauranolan.securityalerttriage.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;
import com.lauranolan.securityalerttriage.model.Alert;
import com.lauranolan.securityalerttriage.model.EventProcessingResult;
import java.util.Optional;
import com.lauranolan.securityalerttriage.repository.AlertRepository;

@Service
public class SecurityEventService {

    private final SecurityEventRepository securityEventRepository;
    private final DetectionEngine detectionEngine;
    private final AlertRepository alertRepository;

    public SecurityEventService(
            SecurityEventRepository securityEventRepository,
            DetectionEngine detectionEngine,
            AlertRepository alertRepository
    ) {
        this.securityEventRepository = securityEventRepository;
        this.detectionEngine = detectionEngine;
        this.alertRepository = alertRepository;
    }

    public EventProcessingResult processEvent(SecurityEvent event) {
        SecurityEvent savedEvent = securityEventRepository.save(event);

        Optional<Alert> alert = detectionEngine.evaluate(savedEvent);
        alert.ifPresent(alertRepository::save);
        return new EventProcessingResult(savedEvent, alert);
    }
}
