package ma.ens.security.jwtapiclean;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service personnalisé pour charger les détails des utilisateurs
 * Custom service to load user details
 *
 * Implémente UserDetailsService pour l'intégration Spring Security
 * Implements UserDetailsService for Spring Security integration
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Charge un utilisateur par son nom d'utilisateur
     * Loads a user by username
     *
     * Cette méthode est appelée automatiquement par Spring Security
     * This method is automatically called by Spring Security
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Chargement de l'utilisateur / Loading user: {}", username);

        return userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.error("Utilisateur non trouvé / User not found: {}", username);
                    return new UsernameNotFoundException("Utilisateur non trouvé / User not found: " + username);
                });
    }
}