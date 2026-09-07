package com.lauranolan.securityalerttriage.detection;

import com.lauranolan.securityalerttriage.model.*;
import org.springframework.stereotype.Component;
import com.lauranolan.securityalerttriage.repository.SecurityEventRepository;

import java.util.List;
import java.util.Optional;
import java.time.LocalDateTime;
import java.util.Set;
import java.util.HashSet;
import java.time.LocalTime;
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
            LocalTime eventTime = event.getTimestamp().toLocalTime();
            LocalTime expectedStart = LocalTime.of(7, 0);
            LocalTime expectedEnd = LocalTime.of(20, 0);

            boolean outsideExpectedHours =
                    eventTime.isBefore(expectedStart) || eventTime.isAfter(expectedEnd);

            AlertSeverity alertSeverity;
            if (sourceIps.size()> 1 || devices.size() > 1 || outsideExpectedHours) {
                alertSeverity = AlertSeverity.HIGH;
            }
            else{
                alertSeverity = AlertSeverity.MEDIUM;
            }

            String reason = failedLoginCount + " failed login attempts within 5 minutes";

            if (sourceIps.size() > 1) {
                reason += "; multiple source IPs detected";
            }

            if (devices.size() > 1) {
                reason += "; multiple devices detected";
            }

            if (outsideExpectedHours) {
                reason += "; activity occurred outside expected access hours";
            }


            return Optional.of(
            new Alert(
                event.getUser(),
                AlertType.REPEATED_FAILED_LOGIN,
                    reason,
                event.getTimestamp(),
                    sourceIps,
                    devices,
                    alertSeverity
            )
           );


        }


        return Optional.empty();
    }
}
