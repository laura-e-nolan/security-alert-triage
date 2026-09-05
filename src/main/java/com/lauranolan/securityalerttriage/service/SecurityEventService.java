package com.lauranolan.securityalerttriage.service;

import com.lauranolan.securityalerttriage.detection.DetectionEngine;
import com.lauranolan.securityalerttriage.model.SecurityEvent;
import com.lauranolan.securityalerttriage.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;

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

    public SecurityEvent processEvent(SecurityEvent event) {
        SecurityEvent savedEvent = securityEventRepository.save(event);

        detectionEngine.evaluate(savedEvent);

        return savedEvent;
    }
}
