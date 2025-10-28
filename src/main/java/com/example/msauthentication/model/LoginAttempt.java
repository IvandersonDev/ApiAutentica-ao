package com.example.msauthentication.model;

import java.time.Instant;

public class LoginAttempt {
    public String email;
    public int attemptCount;
    public Instant lastAttemptTime;
    public Instant blockedUntil;
    public boolean isBlocked;

    public LoginAttempt() {
        this.attemptCount = 0;
        this.isBlocked = false;
    }

    public LoginAttempt(String email) {
        this.email = email;
        this.attemptCount = 0;
        this.isBlocked = false;
        this.lastAttemptTime = Instant.now();
    }

    public void incrementAttempt() {
        this.attemptCount++;
        this.lastAttemptTime = Instant.now();
    }

    public void resetAttempts() {
        this.attemptCount = 0;
        this.isBlocked = false;
        this.blockedUntil = null;
    }

    public void blockForMinutes(int minutes) {
        this.isBlocked = true;
        this.blockedUntil = Instant.now().plusSeconds(minutes * 60L);
    }

    public boolean isCurrentlyBlocked() {
        if (!isBlocked) {
            return false;
        }
        
        if (blockedUntil != null && Instant.now().isAfter(blockedUntil)) {
            resetAttempts();
            return false;
        }
        
        return true;
    }
}

