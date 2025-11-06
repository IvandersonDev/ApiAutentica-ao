package com.example.msauthentication.controller;

import com.example.msauthentication.helper.AuthHelper;
import com.example.msauthentication.model.User;
import com.example.msauthentication.service.AuthService;
import com.example.msauthentication.service.PasswordRecoveryService;
import com.example.msauthentication.service.RateLimitService;
import com.example.msauthentication.service.ThrottlingService;
import com.example.msauthentication.service.TokenService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final RateLimitService rateLimitService;
    private final ThrottlingService throttlingService;
    private final TokenService tokenService;
    private final PasswordRecoveryService passwordRecoveryService;

    public AuthController(
        AuthService authService,
        RateLimitService rateLimitService,
        ThrottlingService throttlingService,
        TokenService tokenService,
        PasswordRecoveryService passwordRecoveryService
    ) {
        this.authService = authService;
        this.rateLimitService = rateLimitService;
        this.throttlingService = throttlingService;
        this.tokenService = tokenService;
        this.passwordRecoveryService = passwordRecoveryService;
    }

    @PostMapping("/signup")
    public String signup(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String password = body.get("password");
        String name = body.getOrDefault("name", body.get("full_name"));

        if (!AuthHelper.validEmail(email)) {
            return "email ruim";
        }
        if (!AuthHelper.validPassword(password)) {
            return "senha ruim";
        }
        if (!AuthHelper.validName(name)) {
            return "nome ruim";
        }
        if (authService.emailExists(email)) {
            return "ja tem";
        }

        authService.registerUser(name.trim(), email.trim().toLowerCase(), password);
        return "cadastrado";
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String password = body.get("password");

        if (!AuthHelper.validEmail(email)) {
            return ResponseEntity.badRequest()
                .body(Map.of("message", "Email invalido"));
        }

        if (rateLimitService.isUserBlocked(email)) {
            long remainingMinutes = rateLimitService.getRemainingBlockTimeMinutes(email);
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(Map.of("message", "Conta bloqueada por " + remainingMinutes + " minutos"));
        }

        Optional<User> optionalUser = authService.findByEmail(email);
        if (optionalUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Credenciais invalidas"));
        }

        User user = optionalUser.get();
        if (password != null && password.equals(user.getPassword())) {
            rateLimitService.resetAttempts(email);
            authService.markLoggedIn(user, true);

            String token = tokenService.generateToken(email);

            return ResponseEntity.ok(Map.of(
                "message", "Login realizado com sucesso",
                "token", token,
                "userId", user.getId()
            ));
        }

        boolean isNowBlocked = rateLimitService.recordFailedAttempt(email);
        if (isNowBlocked) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(Map.of("message", "Muitas tentativas. Bloqueado por 10 minutos"));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(Map.of("message", "Credenciais invalidas"));
    }

    @GetMapping("/rate-limit-status")
    public Map<String, Object> getRateLimitStatus(@RequestParam String email) {
        if (!AuthHelper.validEmail(email)) {
            return Map.of("error", "email invalido");
        }

        boolean isBlocked = rateLimitService.isUserBlocked(email);
        long remainingMinutes = rateLimitService.getRemainingBlockTimeMinutes(email);

        return Map.of(
            "email", email,
            "isBlocked", isBlocked,
            "remainingMinutes", remainingMinutes
        );
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || authHeader.trim().isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Token nao fornecido"));
        }

        String token = authHeader.startsWith("Bearer ") ? authHeader.substring(7) : authHeader;

        if (!throttlingService.isAllowed(token)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(Map.of("message", "Muitas requisicoes. Aguarde 1 minuto"));
        }

        if (!tokenService.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Token invalido ou expirado"));
        }

        String email = tokenService.extractEmail(token);
        if (email == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Token invalido"));
        }

        Optional<User> optionalUser = authService.findByEmail(email);
        if (optionalUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("message", "Usuario nao encontrado"));
        }

        User user = optionalUser.get();
        Instant createdAt = user.getCreatedAt();

        return ResponseEntity.ok(Map.of(
            "id", user.getId(),
            "email", user.getEmail(),
            "name", user.getName(),
            "createdAt", createdAt != null ? createdAt.toString() : ""
        ));
    }

    @PostMapping("/password-recovery/request")
    public ResponseEntity<?> requestPasswordRecovery(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String name = body.getOrDefault("name", body.get("full_name"));

        if (!AuthHelper.validEmail(email) || !AuthHelper.validName(name)) {
            return ResponseEntity.badRequest()
                .body(Map.of("message", "Dados invalidos"));
        }

        Optional<User> optionalUser = authService.findByEmail(email);
        if (optionalUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("message", "Usuario nao encontrado"));
        }

        User user = optionalUser.get();
        if (user.getName() == null || !secureEquals(user.getName(), name)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Dados de validacao incorretos"));
        }

        String token = passwordRecoveryService.issueToken(email);

        return ResponseEntity.ok(Map.of(
            "message", "Token de recuperacao gerado. Utilize o token enviado para concluir o processo.",
            "recoveryToken", token
        ));
    }

    @PostMapping("/password-recovery/validate")
    public ResponseEntity<?> validateRecoveryToken(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String token = body.get("token");

        PasswordRecoveryService.PasswordValidationResult result = passwordRecoveryService.validateToken(email, token);

        if (result.locked()) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(Map.of("message", "Muitas tentativas invalidas. Aguarde alguns minutos."));
        }

        if (!result.valid()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Token invalido ou expirado"));
        }

        return ResponseEntity.ok(Map.of("message", "Token valido"));
    }

    @PostMapping("/password-recovery/reset")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String token = body.get("token");
        String newPassword = body.get("new_password");

        if (!AuthHelper.validEmail(email) || !AuthHelper.validPassword(newPassword)) {
            return ResponseEntity.badRequest()
                .body(Map.of("message", "Dados invalidos"));
        }

        Optional<User> optionalUser = authService.findByEmail(email);
        if (optionalUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("message", "Usuario nao encontrado"));
        }

        PasswordRecoveryService.PasswordValidationResult result = passwordRecoveryService.validateToken(email, token);
        if (result.locked()) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(Map.of("message", "Muitas tentativas invalidas. Aguarde alguns minutos."));
        }

        if (!result.valid()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Token invalido ou expirado"));
        }

        authService.updatePassword(optionalUser.get(), newPassword);
        passwordRecoveryService.invalidateToken(email);
        rateLimitService.resetAttempts(email);

        return ResponseEntity.ok(Map.of("message", "Senha atualizada com sucesso"));
    }

    private boolean secureEquals(String value, String expected) {
        if (value == null || expected == null) {
            return false;
        }
        byte[] valueBytes = value.getBytes(StandardCharsets.UTF_8);
        byte[] expectedBytes = expected.getBytes(StandardCharsets.UTF_8);
        return java.security.MessageDigest.isEqual(valueBytes, expectedBytes);
    }
}
