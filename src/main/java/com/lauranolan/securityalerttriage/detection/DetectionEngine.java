package com.lauranolan.securityalerttriage.detection;

import org.springframework.stereotype.Component;
import com.lauranolan.securityalerttriage.repository.SecurityEventRepository;
import com.lauranolan.securityalerttriage.model.Alert;
import com.lauranolan.securityalerttriage.model.EventOutcome;
import com.lauranolan.securityalerttriage.model.EventType;
import com.lauranolan.securityalerttriage.model.SecurityEvent;
import com.lauranolan.securityalerttriage.model.AlertType;

import java.util.List;
import java.util.Optional;
import java.time.LocalDateTime;
import java.util.Set;
import java.util.HashSet;
@Component

public class DetectionEngine {

    private final SecurityEventRepository securityEventRepository;

    public DetectionEngine(SecurityEventRepository securityEventRepository) {
        this.securityEventRepository = securityEventRepository;
    }

    public Optional<Alert> evaluate(SecurityEvent event) {
        if (event.getEventType() != EventType.LOGIN || event.getOutcome() != EventOutcome.FAILURE) {
            return Optional.empty();
        }
        LocalDateTime windowStart = event.getTimestamp().minusMinutes(5);
        LocalDateTime windowEnd = event.getTimestamp();


        long failedLoginCount =
                securityEventRepository.countByUserAndEventTypeAndOutcomeAndTimestampBetween(
                        event.getUser(),
                        EventType.LOGIN,
                        EventOutcome.FAILURE,
                        windowStart,
                        windowEnd
                );

        List<SecurityEvent> failedLogins =
                securityEventRepository.findByUserAndEventTypeAndOutcomeAndTimestampBetween(
                        event.getUser(),
                        EventType.LOGIN,
                        EventOutcome.FAILURE,
                        windowStart,
                        windowEnd
                );
        Set<String> sourceIps = new HashSet<>();
        Set<String> devices = new HashSet<>();

        for (SecurityEvent failedLogin : failedLogins) {
            sourceIps.add(failedLogin.getSourceIp());
            devices.add(failedLogin.getDevice());
        }

        if (failedLoginCount >= 4){
            return Optional.of(
            new Alert(
                event.getUser(),
                AlertType.REPEATED_FAILED_LOGIN,
                failedLoginCount + " failed login attempts within 5 minutes",
                event.getTimestamp(),
                    sourceIps,
                    devices
            )
           );

        }


        return Optional.empty();
    }
}
