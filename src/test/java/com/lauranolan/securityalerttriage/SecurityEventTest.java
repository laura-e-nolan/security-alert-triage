package com.lauranolan.securityalerttriage;

import com.lauranolan.securityalerttriage.model.EventOutcome;
import com.lauranolan.securityalerttriage.model.EventType;
import com.lauranolan.securityalerttriage.model.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;
public class SecurityEventTest {
    @Test
    void createsLoginEvent() {
        SecurityEvent event = new SecurityEvent(
                LocalDateTime.of(2026, 9, 2, 14, 30),
                "Sheldon",
                EventType.LOGIN,
                "10.20.5.17",
                "PHY-LT-04",
                null,
                EventOutcome.SUCCESS
        );
        assertEquals("Sheldon", event.getUser());
        assertEquals(EventType.LOGIN, event.getEventType());
        assertEquals("10.20.5.17", event.getSourceIp());
        assertEquals("PHY-LT-04", event.getDevice());
        assertNull(event.getResource());
        assertEquals(EventOutcome.SUCCESS, event.getOutcome());
        assertEquals(LocalDateTime.of(2026, 9, 2, 14, 30), event.getTimestamp());
        assertNotNull(event.getId());
    }

    @Test
    void createsFileAccessEvent() {
    SecurityEvent event = new SecurityEvent(
            LocalDateTime.of(2026,9,3,12,30),
            "Penny",
            EventType.FILE_ACCESS,
            "10.20.5.22",
            "CF-WS-05",
            "schedule.xlsx",
            EventOutcome.SUCCESS
    );
    assertEquals("Penny", event.getUser());
    assertEquals(EventType.FILE_ACCESS,event.getEventType() );
    assertEquals("10.20.5.22", event.getSourceIp());
    assertEquals("CF-WS-05", event.getDevice());
    assertEquals("schedule.xlsx", event.getResource());
    assertEquals(EventOutcome.SUCCESS, event.getOutcome());
    assertEquals(LocalDateTime.of(2026,9,3,12,30),event.getTimestamp());
    assertNotNull(event.getId());
    }
}
