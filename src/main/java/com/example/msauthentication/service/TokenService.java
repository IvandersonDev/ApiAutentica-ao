package com.example.msauthentication.service;

import com.example.msauthentication.config.TokenEncryptionProperties;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Service
public class TokenService {

    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int IV_LENGTH_BYTES = 12;

    private final SecureRandom secureRandom = new SecureRandom();
    private final SecretKey secretKey;
    private final long ttlMillis;

    public TokenService(TokenEncryptionProperties properties) {
        this.secretKey = buildSecretKey(properties);
        this.ttlMillis = properties.getTtlDuration().toMillis();
    }

    public String generateToken(String email) {
        if (!StringUtils.hasText(email)) {
            throw new IllegalArgumentException("Email must be provided to generate a token");
        }

        long expiresAt = Instant.now().plusMillis(ttlMillis).toEpochMilli();
        String payload = email.trim().toLowerCase() + ":" + expiresAt + ":" + UUID.randomUUID();
        return encrypt(payload);
    }

    public boolean validateToken(String encryptedToken) {
        TokenPayload payload = decryptTokenInternal(encryptedToken);
        if (payload == null) {
            return false;
        }

        return payload.expiresAt > Instant.now().toEpochMilli();
    }

    public String extractEmail(String encryptedToken) {
        TokenPayload payload = decryptTokenInternal(encryptedToken);
        return payload != null ? payload.email : null;
    }

    private TokenPayload decryptTokenInternal(String encryptedToken) {
        if (!StringUtils.hasText(encryptedToken)) {
            return null;
        }

        try {
            String decrypted = decrypt(encryptedToken);
            String[] parts = decrypted.split(":");
            if (parts.length != 3) {
                return null;
            }
            String email = parts[0];
            long expiresAt = Long.parseLong(parts[1]);
            return new TokenPayload(email, expiresAt);
        } catch (Exception e) {
            return null;
        }
    }

    private String encrypt(String data) {
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            byte[] ciphertext = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

            ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
            buffer.put(iv);
            buffer.put(ciphertext);

            return Base64.getEncoder().encodeToString(buffer.array());
        } catch (Exception e) {
            throw new IllegalStateException("Erro ao criptografar token: " + e.getMessage(), e);
        }
    }

    private String decrypt(String encryptedData) {
        try {
            byte[] decoded = Base64.getDecoder().decode(encryptedData);

            byte[] iv = new byte[IV_LENGTH_BYTES];
            byte[] ciphertext = new byte[decoded.length - IV_LENGTH_BYTES];

            ByteBuffer buffer = ByteBuffer.wrap(decoded);
            buffer.get(iv);
            buffer.get(ciphertext);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            byte[] decrypted = cipher.doFinal(ciphertext);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Erro ao descriptografar token: " + e.getMessage(), e);
        }
    }

    private SecretKey buildSecretKey(TokenEncryptionProperties properties) {
        byte[] keyBytes = properties.getSecretKeyBytes();
        return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
    }

    private record TokenPayload(String email, long expiresAt) {
    }
}

