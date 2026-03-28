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
 * Repository pour la gestion des utilisateurs
 * Repository for user management
 */
@Repository
public interface UserRepository extends JpaRepository<AppUser, String> {

    /**
     * Recherche un utilisateur par son nom d'utilisateur
     * Find a user by username
     */
    Optional<AppUser> findByUsername(String username);

    /**
     * Recherche un utilisateur par son email
     * Find a user by email
     */
    Optional<AppUser> findByEmail(String email);

    /**
     * Vérifie si un nom d'utilisateur existe
     * Checks if a username exists
     */
    boolean existsByUsername(String username);

    /**
     * Vérifie si un email existe
     * Checks if an email exists
     */
    boolean existsByEmail(String email);

    /**
     * Met à jour la date de dernière connexion d'un utilisateur
     * Updates a user's last login date
     */
    @Modifying
    @Transactional
    @Query("UPDATE AppUser u SET u.lastLogin = :lastLogin WHERE u.username = :username")
    void updateLastLogin(@Param("username") String username, @Param("lastLogin") LocalDateTime lastLogin);
}