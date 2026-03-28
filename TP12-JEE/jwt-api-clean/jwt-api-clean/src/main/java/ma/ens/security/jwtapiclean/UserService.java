package ma.ens.security.jwtapiclean;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

/**
 * Service de gestion des utilisateurs
 * User management service
 *
 * Contient la logique métier pour les opérations sur les utilisateurs
 * Contains business logic for user operations
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Trouve un utilisateur par son nom d'utilisateur
     * Find a user by username
     */
    @Transactional(readOnly = true)
    public AppUser findByUsername(String username) {
        log.debug("Recherche utilisateur par username / Find user by username: {}", username);
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé / User not found: " + username));
    }

    /**
     * Trouve un utilisateur par son ID
     * Find a user by ID
     */
    @Transactional(readOnly = true)
    public AppUser findById(String id) {
        log.debug("Recherche utilisateur par ID / Find user by ID: {}", id);
        return userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé / User not found: " + id));
    }

    /**
     * Récupère tous les utilisateurs
     * Get all users
     */
    @Transactional(readOnly = true)
    public List<AppUser> findAll() {
        log.debug("Récupération de tous les utilisateurs / Getting all users");
        return userRepository.findAll();
    }

    /**
     * Met à jour le profil d'un utilisateur
     * Update user profile
     */
    @Transactional
    public AppUser updateProfile(String username, Map<String, String> updates) {
        log.info("Mise à jour du profil pour / Updating profile for: {}", username);

        AppUser user = findByUsername(username);

        if (updates.containsKey("email")) {
            String newEmail = updates.get("email");
            if (!user.getEmail().equals(newEmail) && userRepository.existsByEmail(newEmail)) {
                throw new RuntimeException("Email déjà utilisé / Email already in use");
            }
            user.setEmail(newEmail);
            log.debug("Email mis à jour / Email updated");
        }

        if (updates.containsKey("fullName")) {
            user.setFullName(updates.get("fullName"));
            log.debug("Nom complet mis à jour / Full name updated");
        }

        if (updates.containsKey("password")) {
            user.setPassword(passwordEncoder.encode(updates.get("password")));
            log.debug("Mot de passe mis à jour / Password updated");
        }

        return userRepository.save(user);
    }

    /**
     * Supprime un utilisateur
     * Delete a user
     */
    @Transactional
    public void deleteUser(String userId) {
        log.info("Suppression de l'utilisateur / Deleting user: {}", userId);
        AppUser user = findById(userId);
        userRepository.delete(user);
        log.info("Utilisateur supprimé / User deleted: {}", userId);
    }
}