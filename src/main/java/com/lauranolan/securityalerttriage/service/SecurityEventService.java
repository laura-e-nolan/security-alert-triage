package com.lauranolan.securityalerttriage.service;

import org.springframework.stereotype.Service;
import com.lauranolan.securityalerttriage.model.SecurityEvent;
import com.lauranolan.securityalerttriage.repository.SecurityEventRepository;

@Service
public class SecurityEventService {
    public SecurityEvent processEvent(SecurityEvent event) {
        return securityEventRepository.save(event);
    }

    private final SecurityEventRepository securityEventRepository;

    public SecurityEventService(SecurityEventRepository securityEventRepository) {
        this.securityEventRepository = securityEventRepository;
    }
}
