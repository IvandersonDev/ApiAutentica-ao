package com.example.msauthentication.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ThrottlingService {

    private static final Logger LOGGER = LoggerFactory.getLogger(ThrottlingService.class);
    private static final String REDIS_KEY_PREFIX = "auth:me:throttle:";
    private static final int MAX_REQUESTS_PER_MINUTE = 10;
    private static final int TIME_WINDOW_SECONDS = 60;

    private final Map<String, RequestInfo> fallbackCache = new ConcurrentHashMap<>();
    private final StringRedisTemplate redisTemplate;

    public ThrottlingService(ObjectProvider<StringRedisTemplate> redisTemplateProvider) {
        this.redisTemplate = redisTemplateProvider.getIfAvailable();
    }

    public boolean isAllowed(String identifier) {
        if (!StringUtils.hasText(identifier)) {
            return false;
        }

        String cacheKey = buildCacheKey(identifier);

        if (redisTemplate != null) {
            try {
                return evaluateWithRedis(cacheKey);
            } catch (RuntimeException ex) {
                LOGGER.warn("Falling back to in-memory throttling due to Redis error: {}", ex.getMessage());
            }
        }

        return evaluateWithFallback(cacheKey);
    }

    private boolean evaluateWithRedis(String key) {
        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null && count == 1L) {
            redisTemplate.expire(key, Duration.ofSeconds(TIME_WINDOW_SECONDS));
        }

        return count != null && count <= MAX_REQUESTS_PER_MINUTE;
    }

    private boolean evaluateWithFallback(String key) {
        RequestInfo info = fallbackCache.computeIfAbsent(key, k -> new RequestInfo());
        Instant now = Instant.now();

        if (info.windowStart == null || now.isAfter(info.windowStart.plusSeconds(TIME_WINDOW_SECONDS))) {
            info.windowStart = now;
            info.requestCount = 1;
            return true;
        }

        if (info.requestCount >= MAX_REQUESTS_PER_MINUTE) {
            return false;
        }

        info.requestCount++;
        return true;
    }

    private String buildCacheKey(String identifier) {
        String normalized = identifier.trim().toLowerCase();
        return REDIS_KEY_PREFIX + sha256(normalized);
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }

    private static class RequestInfo {
        Instant windowStart;
        int requestCount;
    }
}
