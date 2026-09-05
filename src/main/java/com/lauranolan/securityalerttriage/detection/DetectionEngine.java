package com.lauranolan.securityalerttriage.detection;

import org.springframework.stereotype.Component;
import com.lauranolan.securityalerttriage.repository.SecurityEventRepository;
import com.lauranolan.securityalerttriage.model.Alert;
import com.lauranolan.securityalerttriage.model.EventOutcome;
import com.lauranolan.securityalerttriage.model.EventType;
import com.lauranolan.securityalerttriage.model.SecurityEvent;
import com.lauranolan.securityalerttriage.model.AlertType;

import java.util.Optional;
import java.time.LocalDateTime;
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
        if (failedLoginCount >= 4){
            return Optional.of(
            new Alert(
                event.getUser(),
                AlertType.REPEATED_FAILED_LOGIN,
                failedLoginCount + " failed login attempts within 5 minutes",
                event.getTimestamp()
            )
           );

        }
        return Optional.empty();
    }
}
