# Mini Proyecto: API Segura con JWT

## Objetivo
Crear una API REST básica con autenticación JWT usando Spring Security donde existan dos roles: USER y ADMIN.

## Requerimientos Básicos

### Usuario
```java
public class Usuario {
    private Long id;
    private String email;
    private String password;
    private String role; // "ROLE_USER" o "ROLE_ADMIN"
}
```

### Endpoints a Implementar

1. Públicos:
   - POST /api/auth/register - Registro de usuario
   - POST /api/auth/login - Login (devuelve JWT)

2. Protegidos:
   - GET /api/user/info - Acceso para ROLE_USER y ROLE_ADMIN
   - GET /api/admin/dashboard - Solo acceso para ROLE_ADMIN

## Tareas Día 1

1. Configurar dependencias en pom.xml:
   - spring-boot-starter-security
   - jjwt-api
   - jjwt-impl
   - jjwt-jackson

2. Implementar clases base:
```java
@Service
public class JwtService {
    private static final String SECRET_KEY = "tu_clave_secreta";
    
    public String generateToken(String username) {
        // Implementar generación de token
    }
    
    public boolean validateToken(String token) {
        // Implementar validación
    }
}

@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        // Implementar filtro JWT
    }
}
```

## Tareas Día 2

1. Implementar controladores:
```java
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegistroDto registro) {
        // Implementar registro
    }
    
    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginDto login) {
        // Implementar login
    }
}

@RestController
public class ResourceController {
    @GetMapping("/api/user/info")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity userInfo() {
        return ResponseEntity.ok("Info de usuario");
    }
    
    @GetMapping("/api/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity adminDashboard() {
        return ResponseEntity.ok("Panel de admin");
    }
}
```

2. Configurar seguridad:
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }
}
```

## Pruebas Requeridas

1. Registro:
```bash
curl -X POST http://localhost:8080/api/auth/register \
-H "Content-Type: application/json" \
-d '{"email":"test@test.com","password":"password","role":"ROLE_USER"}'
```

2. Login:
```bash
curl -X POST http://localhost:8080/api/auth/login \
-H "Content-Type: application/json" \
-d '{"email":"test@test.com","password":"password"}'
```

3. Acceso a endpoint protegido:
```bash
curl http://localhost:8080/api/user/info \
-H "Authorization: Bearer "
```

## Entregable
- Código en GitHub con README básico
- Colección Postman con las pruebas
- Crear una branch nueva con el desarrollo

## Criterios de Éxito
1. Registro funcional
2. Login devuelve JWT válido
3. Endpoints protegidos validan roles correctamente
4. Manejo básico de errores implementado
