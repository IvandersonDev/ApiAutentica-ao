package com.example.msauthentication.service;

import com.example.msauthentication.config.RateLimitConfig;
import com.example.msauthentication.model.LoginAttempt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

@Service
public class RateLimitService {
    
    private final Map<String, LoginAttempt> loginAttempts = new ConcurrentHashMap<>();
    
    @Autowired
    private RateLimitConfig rateLimitConfig;
    
    public boolean isUserBlocked(String email) {
        if (!rateLimitConfig.isEnabled()) {
            return false;
        }
        
        LoginAttempt attempt = loginAttempts.get(email);
        if (attempt == null) {
            return false;
        }
        
        return attempt.isCurrentlyBlocked();
    }
    
    public boolean recordFailedAttempt(String email) {
        if (!rateLimitConfig.isEnabled()) {
            return false;
        }
        
        LoginAttempt attempt = loginAttempts.computeIfAbsent(email, LoginAttempt::new);
        attempt.incrementAttempt();
        
        if (attempt.attemptCount >= rateLimitConfig.getMaxAttempts()) {
            attempt.blockForMinutes(rateLimitConfig.getBlockDurationMinutes());
            return true;
        }
        
        return false;
    }
    
    public void resetAttempts(String email) {
        LoginAttempt attempt = loginAttempts.get(email);
        if (attempt != null) {
            attempt.resetAttempts();
        }
    }
    
    public LoginAttempt getLoginAttempt(String email) {
        return loginAttempts.get(email);
    }
    
    public long getRemainingBlockTimeMinutes(String email) {
        LoginAttempt attempt = loginAttempts.get(email);
        if (attempt == null || !attempt.isCurrentlyBlocked()) {
            return 0;
        }
        
        if (attempt.blockedUntil == null) {
            return 0;
        }
        
        long remainingSeconds = Instant.now().until(attempt.blockedUntil, ChronoUnit.SECONDS);
        return Math.max(0, remainingSeconds / 60);
    }
    
    public void cleanupOldAttempts() {
        Instant cutoffTime = Instant.now().minusSeconds(rateLimitConfig.getBlockDurationMinutes() * 60L * 2);
        
        loginAttempts.entrySet().removeIf(entry -> {
            LoginAttempt attempt = entry.getValue();
            return attempt.lastAttemptTime != null && 
                   attempt.lastAttemptTime.isBefore(cutoffTime) && 
                   !attempt.isCurrentlyBlocked();
        });
    }
}
