package ma.ens.security.jwtapiclean;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class TestController {

    private final UserService userService;

    @GetMapping("/test")
    public String test() {
        return "Test controller works!";
    }

    @GetMapping("/profile")
    public Map<String, Object> getProfile() {
        AppUser user = userService.findByUsername("hafsa");

        Map<String, Object> profile = new HashMap<>();
        profile.put("id", user.getId());
        profile.put("username", user.getUsername());
        profile.put("email", user.getEmail());
        profile.put("fullName", user.getFullName());
        profile.put("enabled", user.isEnabled());

        return profile;
    }

    // ENDPOINT POUR /api/user/profile (AVEC TOKEN)
    @GetMapping("/user/profile")
    public Map<String, Object> getUserProfile() {
        AppUser user = userService.findByUsername("hafsa");

        Map<String, Object> profile = new HashMap<>();
        profile.put("id", user.getId());
        profile.put("username", user.getUsername());
        profile.put("email", user.getEmail());
        profile.put("fullName", user.getFullName());
        profile.put("roles", user.getRoles().stream().map(role -> role.getName()).toList());
        profile.put("enabled", user.isEnabled());
        profile.put("createdAt", user.getCreatedAt());

        return profile;
    }

    @GetMapping("/dashboard")
    public Map<String, Object> getDashboard() {
        Map<String, Object> dashboard = new HashMap<>();
        dashboard.put("status", "active");
        dashboard.put("message", "Welcome to the dashboard");
        dashboard.put("user", "hafsa");
        return dashboard;
    }

    @GetMapping("/users")
    public Object getUsers() {
        return userService.findAll();
    }
}