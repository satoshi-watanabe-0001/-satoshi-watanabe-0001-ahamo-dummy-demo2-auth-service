package com.ahamo.dummy.demo2.auth.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RateLimitServiceTest {

    private RateLimitService rateLimitService;

    @BeforeEach
    void setUp() {
        rateLimitService = new RateLimitService();
    }

    @Test
    void recordFailedAttempt_FirstAttempt() {
        rateLimitService.recordFailedAttempt("test@example.com");

        assertFalse(rateLimitService.isBlocked("test@example.com"));
    }

    @Test
    void recordFailedAttempt_MaxAttemptsReached() {
        String identifier = "test@example.com";

        for (int i = 0; i < 5; i++) {
            rateLimitService.recordFailedAttempt(identifier);
        }

        assertTrue(rateLimitService.isBlocked(identifier));
    }

    @Test
    void isBlocked_NoAttempts() {
        assertFalse(rateLimitService.isBlocked("test@example.com"));
    }

    @Test
    void clearAttempts_Success() {
        String identifier = "test@example.com";
        rateLimitService.recordFailedAttempt(identifier);

        rateLimitService.clearAttempts(identifier);

        assertFalse(rateLimitService.isBlocked(identifier));
    }
}
