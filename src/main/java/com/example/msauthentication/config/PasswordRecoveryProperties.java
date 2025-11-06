package com.example.msauthentication.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;

@Component
@ConfigurationProperties(prefix = "password-recovery")
public class PasswordRecoveryProperties {

    private long tokenTtlMinutes = 15;
    private String hmacSecret;

    public long getTokenTtlMinutes() {
        return tokenTtlMinutes;
    }

    public void setTokenTtlMinutes(long tokenTtlMinutes) {
        this.tokenTtlMinutes = tokenTtlMinutes;
    }

    public String getHmacSecret() {
        return hmacSecret;
    }

    public void setHmacSecret(String hmacSecret) {
        this.hmacSecret = hmacSecret;
    }

    public Duration getTokenTtl() {
        long safeTtl = tokenTtlMinutes <= 0 ? 15 : tokenTtlMinutes;
        return Duration.ofMinutes(safeTtl);
    }

    public byte[] getHmacKeyBytes() {
        if (!StringUtils.hasText(hmacSecret)) {
            throw new IllegalStateException("password-recovery.hmac-secret must be configured");
        }

        byte[] keyCandidate = decodeSecret(hmacSecret.trim());
        if (keyCandidate.length < 32) {
            keyCandidate = Arrays.copyOf(keyCandidate, 32);
        } else if (keyCandidate.length > 32) {
            keyCandidate = Arrays.copyOf(keyCandidate, 32);
        }
        return keyCandidate;
    }

    private byte[] decodeSecret(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException ignored) {
            return value.getBytes(StandardCharsets.UTF_8);
        }
    }
}
