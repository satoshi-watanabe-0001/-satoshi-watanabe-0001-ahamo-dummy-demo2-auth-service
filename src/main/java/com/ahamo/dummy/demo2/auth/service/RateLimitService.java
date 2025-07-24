package com.ahamo.dummy.demo2.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
@Slf4j
public class RateLimitService {

    private final ConcurrentMap<String, AttemptInfo> attemptCache = new ConcurrentHashMap<>();
    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCKOUT_DURATION_MINUTES = 5;

    public void recordFailedAttempt(String identifier) {
        AttemptInfo info = attemptCache.computeIfAbsent(identifier, k -> new AttemptInfo());
        
        synchronized (info) {
            if (info.isExpired()) {
                info.reset();
            }
            
            info.incrementAttempts();
            
            if (info.getAttempts() >= MAX_ATTEMPTS) {
                info.setBlockedUntil(LocalDateTime.now().plusMinutes(LOCKOUT_DURATION_MINUTES));
                log.warn("Rate limit exceeded for identifier: {}", identifier);
            }
        }
    }

    public boolean isBlocked(String identifier) {
        AttemptInfo info = attemptCache.get(identifier);
        if (info == null) {
            return false;
        }
        
        synchronized (info) {
            if (info.isExpired()) {
                attemptCache.remove(identifier);
                return false;
            }
            
            return info.isBlocked();
        }
    }

    public void clearAttempts(String identifier) {
        attemptCache.remove(identifier);
    }

    private static class AttemptInfo {
        private int attempts = 0;
        private LocalDateTime blockedUntil;
        private LocalDateTime lastAttempt = LocalDateTime.now();

        public void incrementAttempts() {
            this.attempts++;
            this.lastAttempt = LocalDateTime.now();
        }

        public int getAttempts() {
            return attempts;
        }

        public void setBlockedUntil(LocalDateTime blockedUntil) {
            this.blockedUntil = blockedUntil;
        }

        public boolean isBlocked() {
            return blockedUntil != null && LocalDateTime.now().isBefore(blockedUntil);
        }

        public boolean isExpired() {
            return lastAttempt.isBefore(LocalDateTime.now().minusMinutes(LOCKOUT_DURATION_MINUTES));
        }

        public void reset() {
            this.attempts = 0;
            this.blockedUntil = null;
            this.lastAttempt = LocalDateTime.now();
        }
    }
}
