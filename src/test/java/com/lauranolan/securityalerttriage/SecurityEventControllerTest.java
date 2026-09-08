package com.lauranolan.securityalerttriage;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import com.lauranolan.securityalerttriage.controller.SecurityEventController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.transaction.annotation.Transactional;

import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import com.lauranolan.securityalerttriage.repository.AlertRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
@Transactional
public class SecurityEventControllerTest {

    @Autowired
    private SecurityEventController securityEventController;

    @Autowired
    private AlertRepository alertRepository;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(securityEventController).build();
    }

    @Test
    void contextLoads() {
    }

    @Test
    void acceptsSecurityEvent() throws Exception {
        String eventJson = """
            {
              "timestamp": "2026-09-03T02:14:00",
              "user": "Sheldon",
              "eventType": "LOGIN",
              "sourceIp": "10.20.5.17",
              "device": "PHY-LT-04",
              "resource": null,
              "outcome": "FAILURE"
            }
            """;

        mockMvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(eventJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.event.user").value("Sheldon"))
                .andExpect(jsonPath("$.event.eventType").value("LOGIN"))
                .andExpect(jsonPath("$.event.outcome").value("FAILURE"))
                .andExpect(jsonPath("$.event.id").isNotEmpty())
                .andExpect(jsonPath("$.alert").isEmpty());
    }

    @Test
    void returnsAlertAfterFourFailedLogins() throws Exception {

        long alertCountBefore = alertRepository.count();

        String event1Json = """
            {
              "timestamp": "2026-09-05T14:00:00",
              "user": "Sheldon",
              "eventType": "LOGIN",
              "sourceIp": "10.20.5.17",
              "device": "PHY-LT-04",
              "resource": null,
              "outcome": "FAILURE"
            }
            """;

        String event2Json = """
    {
      "timestamp": "2026-09-05T14:01:00",
      "user": "Sheldon",
      "eventType": "LOGIN",
      "sourceIp": "10.20.5.17",
      "device": "PHY-LT-04",
      "resource": null,
      "outcome": "FAILURE"
    }
    """;

        String event3Json = """
    {
      "timestamp": "2026-09-05T14:03:00",
      "user": "Sheldon",
      "eventType": "LOGIN",
      "sourceIp": "10.20.5.17",
      "device": "PHY-LT-04",
      "resource": null,
      "outcome": "FAILURE"
    }
    """;

        String event4Json = """
    {
      "timestamp": "2026-09-05T14:04:00",
      "user": "Sheldon",
      "eventType": "LOGIN",
      "sourceIp": "10.20.5.17",
      "device": "PHY-LT-04",
      "resource": null,
      "outcome": "FAILURE"
    }
    """;

        mockMvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(event1Json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.event.user").value("Sheldon"))
                .andExpect(jsonPath("$.event.eventType").value("LOGIN"))
                .andExpect(jsonPath("$.event.outcome").value("FAILURE"))
                .andExpect(jsonPath("$.event.id").isNotEmpty())
                .andExpect(jsonPath("$.alert").isEmpty());

        mockMvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(event2Json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alert").isEmpty());

        mockMvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(event3Json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alert").isEmpty());

        mockMvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(event4Json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alert").isNotEmpty())
                .andExpect(jsonPath("$.alert.alertType").value("REPEATED_FAILED_LOGIN"))
                .andExpect(jsonPath("$.alert.alertSeverity").value("MEDIUM"))
                .andExpect(jsonPath("$.alert.reason")
                        .value("4 failed login attempts within 5 minutes"));

        assertEquals(alertCountBefore + 1, alertRepository.count());
    }

    @Test
    void returnsHighAlertForMultipleIpsAndDevices() throws Exception {

        String event1Json = """
        {
          "timestamp": "2026-09-05T16:00:00",
          "user": "Sheldon",
          "eventType": "LOGIN",
          "sourceIp": "10.20.5.17",
          "device": "PHY-LT-04",
          "resource": null,
          "outcome": "FAILURE"
        }
        """;

        String event2Json = """
        {
          "timestamp": "2026-09-05T16:01:00",
          "user": "Sheldon",
          "eventType": "LOGIN",
          "sourceIp": "10.20.5.17",
          "device": "PHY-LT-04",
          "resource": null,
          "outcome": "FAILURE"
        }
        """;

        String event3Json = """
        {
          "timestamp": "2026-09-05T16:03:00",
          "user": "Sheldon",
          "eventType": "LOGIN",
          "sourceIp": "10.20.5.17",
          "device": "PHY-LT-04",
          "resource": null,
          "outcome": "FAILURE"
        }
        """;

        String event4Json = """
        {
          "timestamp": "2026-09-05T16:04:00",
          "user": "Sheldon",
          "eventType": "LOGIN",
          "sourceIp": "10.20.5.44",
          "device": "UNKNOWN-LT-02",
          "resource": null,
          "outcome": "FAILURE"
        }
        """;

        mockMvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(event1Json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alert").isEmpty());

        mockMvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(event2Json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alert").isEmpty());

        mockMvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(event3Json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alert").isEmpty());

        mockMvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(event4Json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alert").isNotEmpty())
                .andExpect(jsonPath("$.alert.alertType")
                        .value("REPEATED_FAILED_LOGIN"))
                .andExpect(jsonPath("$.alert.alertSeverity")
                        .value("HIGH"))
                .andExpect(jsonPath("$.alert.reason")
                        .value("4 failed login attempts within 5 minutes; multiple source IPs detected; multiple devices detected"));
    }
}