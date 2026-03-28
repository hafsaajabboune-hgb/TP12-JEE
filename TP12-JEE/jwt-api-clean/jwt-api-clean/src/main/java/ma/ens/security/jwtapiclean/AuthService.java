package ma.ens.security.jwtapiclean;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import ma.ens.security.jwtapiclean.dto.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Service d'authentification
 * Authentication Service
 *
 * Gère la connexion, l'inscription et le rafraîchissement des tokens
 * Handles login, registration and token refresh
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Authentifie un utilisateur et génère les tokens
     * Authenticates a user and generates tokens
     */
    @Transactional
    public AuthResponse authenticate(AuthRequest request) {
        log.info("Tentative de connexion / Login attempt: {}", request.getUsername());

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        AppUser user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé / User not found"));

        userRepository.updateLastLogin(user.getUsername(), LocalDateTime.now());

        String accessToken = jwtTokenProvider.generateAccessToken(authentication);
        String refreshToken = generateRefreshToken(user);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(3600L)
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles().stream().map(AppRole::getName).collect(Collectors.toSet()))
                .build();
    }

    /**
     * Inscrit un nouvel utilisateur
     * Registers a new user
     */
    @Transactional
    public AppUser register(UserRegistrationRequest request) {
        log.info("Nouvelle inscription / New registration: {}", request.getUsername());

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Nom d'utilisateur déjà utilisé / Username already taken");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email déjà utilisé / Email already in use");
        }

        AppUser user = AppUser.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .fullName(request.getFullName())
                .enabled(true)
                .accountNonLocked(true)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .build();

        AppRole defaultRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("Rôle USER non trouvé / USER role not found"));

        Set<AppRole> roles = new HashSet<>();
        roles.add(defaultRole);
        user.setRoles(roles);

        log.info("Utilisateur créé avec succès / User created successfully: {}", request.getUsername());
        return userRepository.save(user);
    }

    /**
     * Rafraîchit le token d'accès
     * Refreshes the access token
     */
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        log.info("Demande de rafraîchissement / Token refresh request");

        RefreshToken refreshToken = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new RuntimeException("Refresh token invalide / Invalid refresh token"));

        if (refreshToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Refresh token expiré / Refresh token expired");
        }

        if (refreshToken.isRevoked()) {
            throw new RuntimeException("Refresh token révoqué / Refresh token revoked");
        }

        AppUser user = refreshToken.getUser();

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(user.getUsername(), null, user.getAuthorities());

        String newAccessToken = jwtTokenProvider.generateAccessToken(authentication);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(request.getRefreshToken())
                .tokenType("Bearer")
                .expiresIn(3600L)
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles().stream().map(AppRole::getName).collect(Collectors.toSet()))
                .build();
    }

    /**
     * Génère un refresh token pour un utilisateur
     * Generates a refresh token for a user
     */
    private String generateRefreshToken(AppUser user) {
        log.debug("Génération refresh token pour / Generating refresh token for: {}", user.getUsername());

        refreshTokenRepository.deleteByUser(user);
        log.debug("Ancien refresh token supprimé / Old refresh token deleted");

        String token = jwtTokenProvider.generateRefreshToken(user.getUsername());

        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .user(user)
                .expiryDate(LocalDateTime.now().plusDays(7))
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshToken);
        log.debug("Nouveau refresh token sauvegardé / New refresh token saved");

        return token;
    }

    /**
     * Déconnecte un utilisateur
     * Logs out a user
     */
    @Transactional
    public void logout(String username) {
        log.info("Déconnexion / Logout: {}", username);

        AppUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé / User not found"));

        refreshTokenRepository.deleteByUser(user);

        log.info("Déconnexion réussie / Logout successful: {}", username);
    }
}