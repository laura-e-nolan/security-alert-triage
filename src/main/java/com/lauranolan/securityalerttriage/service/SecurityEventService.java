package com.lauranolan.securityalerttriage.service;

import org.springframework.stereotype.Service;
import com.lauranolan.securityalerttriage.model.SecurityEvent;

@Service
public class SecurityEventService {
    public SecurityEvent processEvent(SecurityEvent event) {
        return event;
    }
}
