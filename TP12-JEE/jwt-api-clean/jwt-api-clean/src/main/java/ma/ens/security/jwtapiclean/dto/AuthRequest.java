package ma.ens.security.jwtapiclean.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Requête d'authentification
 * Authentication request DTO
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthRequest {

    @NotBlank(message = "Nom d'utilisateur requis / Username required")
    private String username;

    @NotBlank(message = "Mot de passe requis / Password required")
    private String password;
}