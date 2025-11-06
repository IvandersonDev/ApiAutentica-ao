package com.example.msauthentication.service;

import com.example.msauthentication.config.PasswordRecoveryProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class PasswordRecoveryService {

    private static final String TOKEN_KEY_PREFIX = "auth:password-recovery:token:";
    private static final String ATTEMPT_KEY_PREFIX = "auth:password-recovery:attempts:";
    private static final int MAX_VALIDATION_ATTEMPTS = 5;
    private static final int TOKEN_LENGTH_BYTES = 32;

    private final SecureRandom secureRandom = new SecureRandom();
    private final StringRedisTemplate redisTemplate;
    private final PasswordRecoveryProperties properties;
    private final SecretKeySpec hmacKey;
    private final ThreadLocal<Mac> macThreadLocal = ThreadLocal.withInitial(this::createMac);
    private final Map<String, RecoveryToken> fallbackTokens = new ConcurrentHashMap<>();
    private final Map<String, AttemptTracker> fallbackAttempts = new ConcurrentHashMap<>();

    public PasswordRecoveryService(
        PasswordRecoveryProperties properties,
        ObjectProvider<StringRedisTemplate> redisTemplateProvider
    ) {
        this.properties = properties;
        this.redisTemplate = redisTemplateProvider.getIfAvailable();
        this.hmacKey = new SecretKeySpec(properties.getHmacKeyBytes(), "HmacSHA256");
    }

    public String issueToken(String email) {
        if (!StringUtils.hasText(email)) {
            throw new IllegalArgumentException("Email is required");
        }

        String normalizedEmail = normalizeEmail(email);
        String token = generateToken();
        String tokenHash = hashToken(token);

        storeToken(normalizedEmail, tokenHash);
        resetAttempts(normalizedEmail);

        return token;
    }

    public PasswordValidationResult validateToken(String email, String token) {
        if (!StringUtils.hasText(email) || !StringUtils.hasText(token)) {
            boolean locked = recordInvalidAttempt(normalizeEmail(email));
            return new PasswordValidationResult(false, locked);
        }

        String normalizedEmail = normalizeEmail(email);
        String storedHash = retrieveStoredHash(normalizedEmail);

        if (storedHash == null) {
            boolean locked = recordInvalidAttempt(normalizedEmail);
            return new PasswordValidationResult(false, locked);
        }

        String incomingHash = hashToken(token);
        boolean matches = constantTimeEquals(storedHash, incomingHash);
        if (!matches) {
            boolean locked = recordInvalidAttempt(normalizedEmail);
            return new PasswordValidationResult(false, locked);
        }

        resetAttempts(normalizedEmail);
        return new PasswordValidationResult(true, false);
    }

    public void invalidateToken(String email) {
        String normalizedEmail = normalizeEmail(email);
        if (redisTemplate != null) {
            redisTemplate.delete(tokenKey(normalizedEmail));
        } else {
            fallbackTokens.remove(normalizedEmail);
        }
        resetAttempts(normalizedEmail);
    }

    private void storeToken(String normalizedEmail, String tokenHash) {
        Duration ttl = properties.getTokenTtl();
        if (redisTemplate != null) {
            redisTemplate.opsForValue().set(tokenKey(normalizedEmail), tokenHash, ttl);
        } else {
            fallbackTokens.put(normalizedEmail, new RecoveryToken(tokenHash, Instant.now().plus(ttl)));
        }
    }

    private String retrieveStoredHash(String normalizedEmail) {
        if (redisTemplate != null) {
            return redisTemplate.opsForValue().get(tokenKey(normalizedEmail));
        }

        RecoveryToken recoveryToken = fallbackTokens.get(normalizedEmail);
        if (recoveryToken == null) {
            return null;
        }
        if (Instant.now().isAfter(recoveryToken.expiresAt())) {
            fallbackTokens.remove(normalizedEmail);
            return null;
        }
        return recoveryToken.hash();
    }

    private boolean recordInvalidAttempt(String normalizedEmail) {
        if (redisTemplate != null) {
            String key = attemptKey(normalizedEmail);
            Long attempts = redisTemplate.opsForValue().increment(key);
            if (attempts != null && attempts == 1L) {
                redisTemplate.expire(key, properties.getTokenTtl());
            }
            return attempts != null && attempts >= MAX_VALIDATION_ATTEMPTS;
        }

        AttemptTracker tracker = fallbackAttempts.computeIfAbsent(normalizedEmail,
            k -> new AttemptTracker(Instant.now().plus(properties.getTokenTtl())));
        tracker.trimIfExpired(properties.getTokenTtl());
        tracker.count++;
        return tracker.count >= MAX_VALIDATION_ATTEMPTS;
    }

    private void resetAttempts(String normalizedEmail) {
        if (redisTemplate != null) {
            redisTemplate.delete(attemptKey(normalizedEmail));
            return;
        }

        fallbackAttempts.remove(normalizedEmail);
    }

    private String generateToken() {
        byte[] tokenBytes = new byte[TOKEN_LENGTH_BYTES];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    private String hashToken(String token) {
        Mac mac = macThreadLocal.get();
        mac.reset();
        byte[] hmacBytes = mac.doFinal(token.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    private boolean constantTimeEquals(String first, String second) {
        byte[] firstBytes = first.getBytes(StandardCharsets.UTF_8);
        byte[] secondBytes = second.getBytes(StandardCharsets.UTF_8);
        return java.security.MessageDigest.isEqual(firstBytes, secondBytes);
    }

    private Mac createMac() {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(hmacKey);
            return mac;
        } catch (Exception e) {
            throw new IllegalStateException("Unable to initialize HMAC for password recovery", e);
        }
    }

    private String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }

    private String tokenKey(String email) {
        return TOKEN_KEY_PREFIX + email;
    }

    private String attemptKey(String email) {
        return ATTEMPT_KEY_PREFIX + email;
    }

    private record RecoveryToken(String hash, Instant expiresAt) {
    }

    public record PasswordValidationResult(boolean valid, boolean locked) {
    }

    private static class AttemptTracker {
        private int count;
        private Instant expiresAt;

        AttemptTracker(Instant expiresAt) {
            this.count = 0;
            this.expiresAt = expiresAt;
        }

        void trimIfExpired(Duration ttl) {
            if (expiresAt != null && Instant.now().isAfter(expiresAt)) {
                count = 0;
                expiresAt = Instant.now().plus(ttl);
            }
        }
    }
}
