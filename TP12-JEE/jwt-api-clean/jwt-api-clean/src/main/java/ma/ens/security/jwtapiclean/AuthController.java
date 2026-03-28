package ma.ens.security.jwtapiclean;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import ma.ens.security.jwtapiclean.dto.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * Contrôleur d'authentification
 * Authentication Controller
 *
 * Gère les endpoints d'authentification : login, register, refresh, logout
 * Handles authentication endpoints: login, register, refresh, logout
 */
@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Endpoint de connexion
     * Login endpoint
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        log.info("Tentative de connexion / Login attempt: {}", request.getUsername());

        AuthResponse response = authService.authenticate(request);
        log.info("Connexion réussie / Login successful: {}", request.getUsername());

        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint d'inscription
     * Registration endpoint
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@Valid @RequestBody UserRegistrationRequest request) {
        log.info("Nouvelle inscription / New registration: {}", request.getUsername());

        AppUser newUser = authService.register(request);

        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "Inscription réussie / Registration successful");
        response.put("userId", newUser.getId());
        response.put("username", newUser.getUsername());
        response.put("email", newUser.getEmail());

        log.info("Inscription réussie / Registration successful: {}", request.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Endpoint de rafraîchissement de token
     * Token refresh endpoint
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Demande de rafraîchissement / Token refresh request");

        AuthResponse response = authService.refreshToken(request);
        log.debug("Token rafraîchi avec succès / Token refreshed successfully");

        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint de déconnexion
     * Logout endpoint
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest httpRequest) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated()) {
            String username = auth.getName();
            authService.logout(username);
            log.info("Déconnexion réussie / Logout successful: {}", username);
        }

        Map<String, String> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "Déconnexion réussie / Logout successful");

        return ResponseEntity.ok(response);
    }

    /**
     * Vérifie le statut d'authentification
     * Checks authentication status
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> checkAuthStatus() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> response = new HashMap<>();

        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            response.put("authenticated", true);
            response.put("username", auth.getName());
            response.put("authorities", auth.getAuthorities());
        } else {
            response.put("authenticated", false);
            response.put("message", "Non authentifié / Not authenticated");
        }

        return ResponseEntity.ok(response);
    }
}