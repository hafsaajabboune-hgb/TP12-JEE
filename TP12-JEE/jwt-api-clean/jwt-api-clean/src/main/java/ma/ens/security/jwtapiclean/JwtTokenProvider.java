package ma.ens.security.jwtapiclean;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Fournisseur de tokens JWT
 * JWT Token Provider
 *
 * Gère la création, la validation et l'extraction des informations des tokens
 * Handles token creation, validation and information extraction
 */
@Slf4j
@Component
public class JwtTokenProvider {

    @Value("${jwt.secret-key}")
    private String secretKey;

    @Value("${jwt.expiration-time}")
    private long jwtExpirationTime;

    @Value("${jwt.refresh-expiration-time}")
    private long refreshExpirationTime;

    /**
     * Récupère la clé de signature
     * Gets the signing key
     */
    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    /**
     * Génère un token d'accès pour une authentification
     * Generates an access token for an authentication
     */
    public String generateAccessToken(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return generateToken(userDetails.getUsername(), jwtExpirationTime, "access");
    }

    /**
     * Génère un refresh token
     * Generates a refresh token
     */
    public String generateRefreshToken(String username) {
        return generateToken(username, refreshExpirationTime, "refresh");
    }

    /**
     * Méthode principale de génération de token
     * Main token generation method
     */
    private String generateToken(String subject, long expirationTime, String tokenType) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", tokenType);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Extrait le nom d'utilisateur du token
     * Extracts username from token
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extrait la date d'expiration du token
     * Extracts expiration date from token
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extrait un claim spécifique du token
     * Extracts a specific claim from token
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extrait tous les claims du token
     * Extracts all claims from token
     */
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.error("Token expiré / Token expired: {}", e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            log.error("Token non supporté / Unsupported token: {}", e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {
            log.error("Token malformé / Malformed token: {}", e.getMessage());
            throw e;
        } catch (SignatureException e) {
            log.error("Signature invalide / Invalid signature: {}", e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            log.error("Arguments invalides / Invalid arguments: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Vérifie si le token est expiré
     * Checks if token is expired
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Valide le token pour un utilisateur donné
     * Validates token for a given user
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            boolean isValid = username.equals(userDetails.getUsername()) && !isTokenExpired(token);

            if (isValid) {
                log.debug("Token valide pour / Token valid for: {}", username);
            } else {
                log.debug("Token invalide pour / Token invalid for: {}", username);
            }

            return isValid;
        } catch (JwtException e) {
            log.error("Erreur validation token / Token validation error: {}", e.getMessage());
            return false;
        }
    }
}