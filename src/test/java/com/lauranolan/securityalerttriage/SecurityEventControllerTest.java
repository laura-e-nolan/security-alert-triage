package com.lauranolan.securityalerttriage;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import com.lauranolan.securityalerttriage.controller.SecurityEventController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.junit.jupiter.api.BeforeEach;

import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
public class SecurityEventControllerTest {
    @Autowired
    private SecurityEventController securityEventController;

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
                .andExpect(jsonPath("$.user").value("Sheldon"))
                .andExpect(jsonPath("$.eventType").value("LOGIN"))
                .andExpect(jsonPath("$.outcome").value("FAILURE"))
                .andExpect(jsonPath("$.id").isNotEmpty());
    }
}
