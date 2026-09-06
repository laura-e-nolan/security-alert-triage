package com.lauranolan.securityalerttriage;

import com.lauranolan.securityalerttriage.detection.DetectionEngine;
import com.lauranolan.securityalerttriage.repository.SecurityEventRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;
import org.junit.jupiter.api.Test;
import com.lauranolan.securityalerttriage.model.SecurityEvent;
import com.lauranolan.securityalerttriage.model.EventType;
import com.lauranolan.securityalerttriage.model.EventOutcome;
import java.time.LocalDateTime;
import com.lauranolan.securityalerttriage.model.Alert;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.assertTrue;
import com.lauranolan.securityalerttriage.model.AlertType;
import static org.junit.jupiter.api.Assertions.assertEquals;
import com.lauranolan.securityalerttriage.model.AlertSeverity;

@SpringBootTest
@Transactional
public class DetectionEngineTest {
    @Autowired
    private SecurityEventRepository securityEventRepository;

    @Autowired
    private DetectionEngine detectionEngine;

    @Test
    void createsAlertAfterFourFailedLogins() {

        SecurityEvent event1 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 14, 0),
                "Sheldon",
                EventType.LOGIN,
                "10.20.5.17",
                "PHY-LT-04",
                null,
                EventOutcome.FAILURE
        );

        SecurityEvent event2 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 14, 1),
                "Sheldon",
                EventType.LOGIN,
                "10.20.5.17",
                "PHY-LT-04",
                null,
                EventOutcome.FAILURE
        );

        SecurityEvent event3 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 14, 3),
                "Sheldon",
                EventType.LOGIN,
                "10.20.5.17",
                "PHY-LT-04",
                null,
                EventOutcome.FAILURE
        );

        SecurityEvent event4 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 14, 4),
                "Sheldon",
                EventType.LOGIN,
                "10.20.5.17",
                "PHY-LT-04",
                null,
                EventOutcome.FAILURE
        );

        securityEventRepository.save(event1);
        securityEventRepository.save(event2);
        securityEventRepository.save(event3);
        securityEventRepository.save(event4);
        Optional<Alert> result = detectionEngine.evaluate(event4);
        assertTrue(result.isPresent());

        assertEquals(
                AlertType.REPEATED_FAILED_LOGIN,
                result.get().getAlertType()
        );

        assertTrue(
                result.get().getSourceIps().contains("10.20.5.17")
        );

        assertTrue(
                result.get().getDevices().contains("PHY-LT-04")
        );

        assertEquals(
            AlertSeverity.MEDIUM,
                result.get().getAlertSeverity()
        );

    }

    @Test
    void doesNotCreateAlertForOnlyThreeFailedLogins() {

        SecurityEvent event1 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 15, 0),
                "Penny",
                EventType.LOGIN,
                "10.20.5.22",
                "CF-WS-05",
                null,
                EventOutcome.FAILURE
        );

        SecurityEvent event2 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 15, 1),
                "Penny",
                EventType.LOGIN,
                "10.20.5.22",
                "CF-WS-05",
                null,
                EventOutcome.FAILURE
        );

        SecurityEvent event3 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 15, 3),
                "Penny",
                EventType.LOGIN,
                "10.20.5.22",
                "CF-WS-05",
                null,
                EventOutcome.FAILURE
        );

        securityEventRepository.save(event1);
        securityEventRepository.save(event2);
        securityEventRepository.save(event3);

        Optional<Alert> result = detectionEngine.evaluate(event3);

        assertTrue(result.isEmpty());
    }

    @Test
    void doesCreateAlertForDifferentIpsAndDevices() {

        SecurityEvent event1 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 16, 0),
                "Sheldon",
                EventType.LOGIN,
                "10.20.5.17",
                "PHY-LT-04",
                null,
                EventOutcome.FAILURE
        );

        SecurityEvent event2 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 16, 1),
                "Sheldon",
                EventType.LOGIN,
                "10.20.5.44",
                "UNKNOWN-LT-02",
                null,
                EventOutcome.FAILURE
        );

        SecurityEvent event3 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 16, 3),
                "Sheldon",
                EventType.LOGIN,
                "10.20.5.17",
                "PHY-LT-04",
                null,
                EventOutcome.FAILURE
        );

        SecurityEvent event4 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 16, 4),
                "Sheldon",
                EventType.LOGIN,
                "10.20.5.44",
                "UNKNOWN-LT-02",
                null,
                EventOutcome.FAILURE
        );

        securityEventRepository.save(event1);
        securityEventRepository.save(event2);
        securityEventRepository.save(event3);
        securityEventRepository.save(event4);

        Optional<Alert> result = detectionEngine.evaluate(event4);

        assertTrue(result.isPresent());

        assertEquals(
                AlertType.REPEATED_FAILED_LOGIN,
                result.get().getAlertType()
        );

        assertTrue(
                result.get().getSourceIps().contains("10.20.5.17")
        );

        assertTrue(
                result.get().getSourceIps().contains("10.20.5.44")
        );

        assertTrue(
                result.get().getDevices().contains("PHY-LT-04")
        );

        assertTrue(
                result.get().getDevices().contains("UNKNOWN-LT-02")
        );

        assertEquals(
                2,
                result.get().getSourceIps().size()
        );

        assertEquals(
                2,
                result.get().getDevices().size()
        );
        assertEquals(
                AlertSeverity.HIGH,
                result.get().getAlertSeverity()
        );
    }
    @Test
    void doesCreateAlertForOutsideExpectedHours(){
        SecurityEvent event1 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 2, 0),
                "Sheldon",
                EventType.LOGIN,
                "10.20.5.17",
                "PHY-LT-04",
                null,
                EventOutcome.FAILURE
        );
        SecurityEvent event2 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 2, 1),
                "Sheldon",
                EventType.LOGIN,
                "10.20.5.17",
                "PHY-LT-04",
                null,
                EventOutcome.FAILURE
        );
        SecurityEvent event3 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 2, 3),
                "Sheldon",
                EventType.LOGIN,
                "10.20.5.17",
                "PHY-LT-04",
                null,
                EventOutcome.FAILURE
        );
        SecurityEvent event4 = new SecurityEvent(
                LocalDateTime.of(2026, 9, 5, 2, 4),
                "Sheldon",
                EventType.LOGIN,
                "10.20.5.17",
                "PHY-LT-04",
                null,
                EventOutcome.FAILURE
        );

        securityEventRepository.save(event1);
        securityEventRepository.save(event2);
        securityEventRepository.save(event3);
        securityEventRepository.save(event4);

        Optional<Alert> result = detectionEngine.evaluate(event4);

        assertTrue(result.isPresent());

        assertEquals(
                AlertSeverity.HIGH,
                result.get().getAlertSeverity()
        );
    }


}

