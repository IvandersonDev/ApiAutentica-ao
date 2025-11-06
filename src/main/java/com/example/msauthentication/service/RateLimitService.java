package com.example.msauthentication.service;

import com.example.msauthentication.config.RateLimitConfig;
import com.example.msauthentication.model.LoginAttempt;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
public class RateLimitService {

    private static final String LOGIN_ATTEMPTS_KEY_PREFIX = "auth:login-attempts:";
    private static final String LOGIN_BLOCK_KEY_PREFIX = "auth:login-block:";

    private final Map<String, LoginAttempt> fallbackAttempts = new ConcurrentHashMap<>();
    private final RateLimitConfig rateLimitConfig;
    private final StringRedisTemplate redisTemplate;

    public RateLimitService(RateLimitConfig rateLimitConfig, ObjectProvider<StringRedisTemplate> redisTemplateProvider) {
        this.rateLimitConfig = rateLimitConfig;
        this.redisTemplate = redisTemplateProvider.getIfAvailable();
    }

    public boolean isUserBlocked(String email) {
        if (!rateLimitConfig.isEnabled()) {
            return false;
        }

        if (redisTemplate != null) {
            Boolean blocked = redisTemplate.hasKey(blockKey(email));
            return Boolean.TRUE.equals(blocked);
        }

        LoginAttempt attempt = fallbackAttempts.get(email);
        if (attempt == null) {
            return false;
        }

        return attempt.isCurrentlyBlocked();
    }

    public boolean recordFailedAttempt(String email) {
        if (!rateLimitConfig.isEnabled()) {
            return false;
        }

        if (redisTemplate != null) {
            return recordAttemptWithRedis(email);
        }

        LoginAttempt attempt = fallbackAttempts.computeIfAbsent(email, LoginAttempt::new);
        attempt.incrementAttempt();

        if (attempt.attemptCount >= rateLimitConfig.getMaxAttempts()) {
            attempt.blockForMinutes(rateLimitConfig.getBlockDurationMinutes());
            return true;
        }

        return false;
    }

    public void resetAttempts(String email) {
        if (redisTemplate != null) {
            redisTemplate.delete(attemptsKey(email));
            redisTemplate.delete(blockKey(email));
            return;
        }

        LoginAttempt attempt = fallbackAttempts.get(email);
        if (attempt != null) {
            attempt.resetAttempts();
        }
    }

    public LoginAttempt getLoginAttempt(String email) {
        if (redisTemplate != null) {
            return null;
        }
        return fallbackAttempts.get(email);
    }

    public long getRemainingBlockTimeMinutes(String email) {
        if (redisTemplate != null) {
            Long ttlSeconds = redisTemplate.getExpire(blockKey(email), TimeUnit.SECONDS);
            if (ttlSeconds == null || ttlSeconds < 0) {
                return 0;
            }
            return Math.max(0, ttlSeconds / 60);
        }

        LoginAttempt attempt = fallbackAttempts.get(email);
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
        if (redisTemplate != null) {
            return;
        }

        Instant cutoffTime = Instant.now().minusSeconds(rateLimitConfig.getBlockDurationMinutes() * 60L * 2);

        fallbackAttempts.entrySet().removeIf(entry -> {
            LoginAttempt attempt = entry.getValue();
            return attempt.lastAttemptTime != null &&
                   attempt.lastAttemptTime.isBefore(cutoffTime) &&
                   !attempt.isCurrentlyBlocked();
        });
    }

    private boolean recordAttemptWithRedis(String email) {
        String attemptsKey = attemptsKey(email);
        Long attempts = redisTemplate.opsForValue().increment(attemptsKey);
        if (attempts != null && attempts == 1L) {
            redisTemplate.expire(attemptsKey, Duration.ofMinutes(rateLimitConfig.getBlockDurationMinutes()));
        }

        if (attempts != null && attempts >= rateLimitConfig.getMaxAttempts()) {
            redisTemplate.opsForValue()
                .set(blockKey(email), "1", Duration.ofMinutes(rateLimitConfig.getBlockDurationMinutes()));
            redisTemplate.delete(attemptsKey);
            return true;
        }

        return false;
    }

    private String attemptsKey(String email) {
        return LOGIN_ATTEMPTS_KEY_PREFIX + email.toLowerCase();
    }

    private String blockKey(String email) {
        return LOGIN_BLOCK_KEY_PREFIX + email.toLowerCase();
    }
}
