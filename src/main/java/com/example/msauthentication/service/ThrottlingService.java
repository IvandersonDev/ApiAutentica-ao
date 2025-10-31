package com.example.msauthentication.service;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

@Service
public class ThrottlingService {
    
    private final Map<String, RequestInfo> requestCache = new ConcurrentHashMap<>();
    
    private static final int MAX_REQUESTS_PER_MINUTE = 10;
    private static final long TIME_WINDOW_SECONDS = 60;
    
    public boolean isAllowed(String identifier) {
        RequestInfo info = requestCache.computeIfAbsent(identifier, k -> new RequestInfo());
        
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
    
    private static class RequestInfo {
        Instant windowStart;
        int requestCount;
    }
}

