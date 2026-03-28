package ma.ens.security.jwtapiclean;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Entité représentant un rôle dans le système
 * Entity representing a role in the system
 *
 * Les rôles définissent les permissions des utilisateurs
 * Roles define user permissions
 */
@Entity
@Table(name = "app_roles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AppRole {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(length = 36, updatable = false, nullable = false)
    private String id;

    @Column(unique = true, nullable = false, length = 50)
    private String name;

    @Column(length = 200)
    private String description;

    @ManyToMany(mappedBy = "roles")
    @Builder.Default
    private Set<AppUser> users = new HashSet<>();

    /**
     * Constructeur avec nom seulement / Constructor with name only
     */
    public AppRole(String name) {
        this.name = name;
    }

    /**
     * Constructeur avec nom et description / Constructor with name and description
     */
    public AppRole(String name, String description) {
        this.name = name;
        this.description = description;
    }

    /**
     * Retourne le nom du rôle avec préfixe pour Spring Security
     * Returns role name with prefix for Spring Security
     */
    public String getSecurityRoleName() {
        return "ROLE_" + this.name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AppRole appRole = (AppRole) o;
        return Objects.equals(id, appRole.id) || Objects.equals(name, appRole.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name);
    }

    @Override
    public String toString() {
        return "AppRole{id='" + id + "', name='" + name + "'}";
    }
}