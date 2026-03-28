package ma.ens.security.jwtapiclean;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

/**
 * Point d'entrée principal de l'application / Main application entry point
 *
 * Cette classe initialise l'application Spring Boot et les données par défaut
 * This class initializes the Spring Boot application and default data
 *
 * @author Hafsa Security Team
 * @version 1.0
 */
@Slf4j
@SpringBootApplication
@RequiredArgsConstructor
public class JwtApiCleanApplication {

	private final PasswordEncoder passwordEncoder;
	private final UserRepository userRepository;
	private final RoleRepository roleRepository;

	public static void main(String[] args) {
		SpringApplication.run(JwtApiCleanApplication.class, args);
		log.info("========================================");
		log.info("DEMARRAGE REUSSI / STARTUP SUCCESSFUL");
		log.info("API JWT SECURISEE / SECURE JWT API");
		log.info("========================================");
	}

	/**
	 * Initialise les données par défaut au démarrage de l'application
	 * Initializes default data when the application starts
	 */
	@Bean
	public CommandLineRunner initData() {
		return args -> {
			log.info("Initialisation de la base de données / Database initialization...");

			// Création des rôles par défaut / Create default roles
			createRoleIfNotFound("USER", "Role utilisateur standard / Standard user role");
			createRoleIfNotFound("ADMIN", "Role administrateur / Administrator role");

			// Création de l'utilisateur hafsa avec les deux rôles
			// Create user hafsa with both roles
			if (!userRepository.existsByUsername("hafsa")) {
				log.info("Création de l'utilisateur hafsa / Creating user hafsa");

				AppRole userRole = roleRepository.findByName("USER")
						.orElseThrow(() -> new RuntimeException("Role USER introuvable / USER role not found"));
				AppRole adminRole = roleRepository.findByName("ADMIN")
						.orElseThrow(() -> new RuntimeException("Role ADMIN introuvable / ADMIN role not found"));

				AppUser hafsa = AppUser.builder()
						.username("hafsa")
						.email("hafsa@secure-api.com")
						.password(passwordEncoder.encode("Ajab@224"))
						.fullName("Hafsa Utilisateur / Hafsa User")
						.enabled(true)
						.roles(Set.of(userRole, adminRole))
						.build();

				userRepository.save(hafsa);
				log.info("Utilisateur hafsa créé - username: hafsa, password: Ajab@224");
				log.info("User hafsa created - username: hafsa, password: Ajab@224");
			}

			log.info("Initialisation terminée / Initialization complete");
			log.info("========================================");
			log.info("API PRETE / API READY");
			log.info("Connexion / Login: POST /auth/login");
			log.info("Utilisateur / User: hafsa");
			log.info("Mot de passe / Password: Ajab@224");
			log.info("========================================");
		};
	}

	/**
	 * Crée un rôle s'il n'existe pas déjà
	 * Creates a role if it doesn't already exist
	 */
	private void createRoleIfNotFound(String roleName, String description) {
		if (!roleRepository.existsByName(roleName)) {
			log.info("Création du rôle / Creating role: {}", roleName);
			AppRole role = AppRole.builder()
					.name(roleName)
					.description(description)
					.build();
			roleRepository.save(role);
		}
	}
}