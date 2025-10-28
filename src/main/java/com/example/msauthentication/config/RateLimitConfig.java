package com.example.msauthentication.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "rate-limit")
public class RateLimitConfig {
    
    private int maxAttempts = 3;
    private int blockDurationMinutes = 10;
    private boolean enabled = true;
    
    public int getMaxAttempts() {
        return maxAttempts;
    }
    
    public void setMaxAttempts(int maxAttempts) {
        this.maxAttempts = maxAttempts;
    }
    
    public int getBlockDurationMinutes() {
        return blockDurationMinutes;
    }
    
    public void setBlockDurationMinutes(int blockDurationMinutes) {
        this.blockDurationMinutes = blockDurationMinutes;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}

