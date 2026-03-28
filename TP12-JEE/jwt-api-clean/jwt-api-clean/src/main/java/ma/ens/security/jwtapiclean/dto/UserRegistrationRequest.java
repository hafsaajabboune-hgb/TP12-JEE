package ma.ens.security.jwtapiclean.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Requête d'inscription utilisateur
 * User registration request DTO
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationRequest {

    @NotBlank(message = "Nom d'utilisateur requis / Username required")
    @Size(min = 3, max = 50, message = "Le nom d'utilisateur doit contenir entre 3 et 50 caractères / Username must be between 3 and 50 characters")
    private String username;

    @NotBlank(message = "Email requis / Email required")
    @Email(message = "Format d'email invalide / Invalid email format")
    private String email;

    @NotBlank(message = "Mot de passe requis / Password required")
    @Size(min = 6, message = "Le mot de passe doit contenir au moins 6 caractères / Password must contain at least 6 characters")
    private String password;

    @NotBlank(message = "Nom complet requis / Full name required")
    private String fullName;
}