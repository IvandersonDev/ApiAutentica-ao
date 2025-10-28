package com.example.msauthentication.controller;

import com.example.msauthentication.helper.AuthHelper;
import com.example.msauthentication.model.User;
import com.example.msauthentication.service.RateLimitService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final List<User> USERS = new ArrayList<>();
    private static int NEXT_ID = 1;
    
    @Autowired
    private RateLimitService rateLimitService;

    @PostMapping("/signup")
    public String signup(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String password = body.get("password");
        String doc = body.get("doc_number");
        String username = body.get("username");
        String fullName = body.get("full_name");
        if (!AuthHelper.validEmail(email)) {
            return "email ruim";
        }
        if (!AuthHelper.validDocument(doc)) {
            return "doc ruim";
        }
        if (!AuthHelper.validPassword(password)) {
            return "senha ruim";
        }
        for (User item : USERS) {
            if (email.equalsIgnoreCase(item.email) || doc.equals(item.docNumber)) {
                return "ja tem";
            }
        }
        User user = new User();
        user.id = NEXT_ID++;
        user.email = email;
        user.docNumber = doc;
        user.password = password;
        user.username = username;
        user.fullName = fullName;
        user.loggedIn = false;
        user.createdAt = Instant.now().toString();
        user.updatedAt = user.createdAt;
        USERS.add(user);
        return "cadastrado";
    }

    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String password = body.get("password");
        
        if (!AuthHelper.validEmail(email)) {
            return "email ruim";
        }
        
        if (rateLimitService.isUserBlocked(email)) {
            long remainingMinutes = rateLimitService.getRemainingBlockTimeMinutes(email);
            return "bloqueado por " + remainingMinutes + " minutos";
        }
        
        User found = findByEmail(email);
        if (found == null) {
            return "nao existe";
        }
        
        if (password != null && password.equals(found.password)) {
            rateLimitService.resetAttempts(email);
            found.loggedIn = true;
            found.updatedAt = Instant.now().toString();
            return "logou";
        } else {
            boolean isNowBlocked = rateLimitService.recordFailedAttempt(email);
            if (isNowBlocked) {
                return "bloqueado por 10 minutos após 3 tentativas";
            }
            return "errou";
        }
    }

    @GetMapping("/rate-limit-status")
    public Map<String, Object> getRateLimitStatus(@RequestParam String email) {
        if (!AuthHelper.validEmail(email)) {
            return Map.of("error", "email inválido");
        }
        
        boolean isBlocked = rateLimitService.isUserBlocked(email);
        long remainingMinutes = rateLimitService.getRemainingBlockTimeMinutes(email);
        
        Map<String, Object> response = Map.of(
            "email", email,
            "isBlocked", isBlocked,
            "remainingMinutes", remainingMinutes
        );
        
        return response;
    }

    private User findByEmail(String email) {
        for (User item : USERS) {
            if (item.email != null && item.email.equalsIgnoreCase(email)) {
                return item;
            }
        }
        return null;
    }

}
