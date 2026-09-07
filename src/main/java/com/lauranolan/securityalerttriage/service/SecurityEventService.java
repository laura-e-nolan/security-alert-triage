package com.lauranolan.securityalerttriage.service;

import com.lauranolan.securityalerttriage.detection.DetectionEngine;
import com.lauranolan.securityalerttriage.model.SecurityEvent;
import com.lauranolan.securityalerttriage.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;
import com.lauranolan.securityalerttriage.model.Alert;
import com.lauranolan.securityalerttriage.model.EventProcessingResult;
import java.util.Optional;

@Service
public class SecurityEventService {

    private final SecurityEventRepository securityEventRepository;
    private final DetectionEngine detectionEngine;

    public SecurityEventService(
            SecurityEventRepository securityEventRepository,
            DetectionEngine detectionEngine
    ) {
        this.securityEventRepository = securityEventRepository;
        this.detectionEngine = detectionEngine;
    }

    public EventProcessingResult processEvent(SecurityEvent event) {
        SecurityEvent savedEvent = securityEventRepository.save(event);

        Optional<Alert> alert = detectionEngine.evaluate(savedEvent);
        return new EventProcessingResult(savedEvent, alert);
    }
}
