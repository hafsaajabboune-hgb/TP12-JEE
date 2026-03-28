package ma.ens.security.jwtapiclean;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository pour la gestion des rôles
 * Repository for role management
 */
@Repository
public interface RoleRepository extends JpaRepository<AppRole, String> {

    /**
     * Recherche un rôle par son nom
     * Find a role by name
     */
    Optional<AppRole> findByName(String name);

    /**
     * Vérifie si un rôle existe
     * Checks if a role exists
     */
    boolean existsByName(String name);
}