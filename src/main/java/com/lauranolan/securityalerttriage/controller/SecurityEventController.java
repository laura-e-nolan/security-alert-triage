package com.lauranolan.securityalerttriage.controller;

import com.lauranolan.securityalerttriage.model.SecurityEvent;
import com.lauranolan.securityalerttriage.service.SecurityEventService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.lauranolan.securityalerttriage.model.EventProcessingResult;

@RestController
@RequestMapping("/api/events")
public class SecurityEventController {

    private final SecurityEventService securityEventService;

    public SecurityEventController(SecurityEventService securityEventService) {
        this.securityEventService = securityEventService;
    }

    @PostMapping
    public EventProcessingResult createEvent(@RequestBody SecurityEvent event) {
        return securityEventService.processEvent(event);
    }
}