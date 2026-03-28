package ma.ens.security.jwtapiclean;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Entité représentant un token de rafraîchissement
 * Entity representing a refresh token
 *
 * Permet d'obtenir un nouveau token d'accès sans se réauthentifier
 * Allows obtaining a new access token without re-authenticating
 */
@Entity
@Table(name = "refresh_tokens")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(length = 36, updatable = false, nullable = false)
    private String id;

    @Column(nullable = false, unique = true, length = 500)
    private String token;

    @OneToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private AppUser user;

    @Column(nullable = false)
    private LocalDateTime expiryDate;

    @Builder.Default
    private boolean revoked = false;
}