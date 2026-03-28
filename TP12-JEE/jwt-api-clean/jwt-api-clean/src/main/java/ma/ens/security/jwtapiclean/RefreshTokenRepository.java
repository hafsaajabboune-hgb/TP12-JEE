package ma.ens.security.jwtapiclean;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Repository pour la gestion des refresh tokens
 * Repository for refresh token management
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

    /**
     * Recherche un refresh token par sa valeur
     * Find a refresh token by its value
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * Recherche un refresh token par utilisateur
     * Find a refresh token by user
     */
    Optional<RefreshToken> findByUser(AppUser user);

    /**
     * Supprime tous les refresh tokens expirés
     * Delete all expired refresh tokens
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :now")
    void deleteAllExpiredTokens(@Param("now") LocalDateTime now);

    /**
     * Supprime tous les refresh tokens d'un utilisateur
     * Delete all refresh tokens for a user
     *
     * @param user L'utilisateur concerné / The user
     */
    @Modifying
    @Transactional
    void deleteByUser(AppUser user);
}