package com.example.msauthentication.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;

@Component
@ConfigurationProperties(prefix = "token.encryption")
public class TokenEncryptionProperties {

    /**
     * Secret used to derive the AES key. Supports either raw text or Base64 encoded strings.
     */
    private String secret;

    /**
     * Token validity window expressed in hours.
     */
    private long ttlHours = 24;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public long getTtlHours() {
        return ttlHours;
    }

    public void setTtlHours(long ttlHours) {
        this.ttlHours = ttlHours;
    }

    public Duration getTtlDuration() {
        long safeTtl = ttlHours <= 0 ? 24 : ttlHours;
        return Duration.ofHours(safeTtl);
    }

    public byte[] getSecretKeyBytes() {
        if (!StringUtils.hasText(secret)) {
            throw new IllegalStateException("token.encryption.secret must be configured");
        }

        byte[] keyCandidate = decodeSecret(secret.trim());
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
