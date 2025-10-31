package com.example.msauthentication.service;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Service
public class TokenService {
    
    private static final String ALGORITHM = "AES";
    private static final String SECRET_KEY = "MySecretKey12345";
    private final SecretKey secretKey;
    
    public TokenService() {
        byte[] keyBytes = new byte[16];
        byte[] secretBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(secretBytes, 0, keyBytes, 0, Math.min(secretBytes.length, keyBytes.length));
        this.secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
    }
    
    public String generateToken(String email) {
        String rawToken = UUID.randomUUID().toString() + ":" + email + ":" + Instant.now().toEpochMilli();
        return encrypt(rawToken);
    }
    
    public String decryptToken(String encryptedToken) {
        try {
            return decrypt(encryptedToken);
        } catch (Exception e) {
            return null;
        }
    }
    
    public boolean validateToken(String encryptedToken) {
        String decrypted = decryptToken(encryptedToken);
        if (decrypted == null) {
            return false;
        }
        
        String[] parts = decrypted.split(":");
        if (parts.length != 3) {
            return false;
        }
        
        try {
            long timestamp = Long.parseLong(parts[2]);
            long now = Instant.now().toEpochMilli();
            long hourInMillis = 60 * 60 * 1000;
            
            return (now - timestamp) < (24 * hourInMillis);
        } catch (Exception e) {
            return false;
        }
    }
    
    public String extractEmail(String encryptedToken) {
        String decrypted = decryptToken(encryptedToken);
        if (decrypted == null) {
            return null;
        }
        
        String[] parts = decrypted.split(":");
        return parts.length >= 2 ? parts[1] : null;
    }
    
    private String encrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao criptografar: " + e.getMessage());
        }
    }
    
    private String decrypt(String encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao descriptografar: " + e.getMessage());
        }
    }
}

