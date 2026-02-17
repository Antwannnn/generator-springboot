package <%= packageName %>.config;

<%_ if (authenticationTypes && authenticationTypes.length > 0) { _%>
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import <%= packageName %>.config.logging.SecurityLogFilter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.http.SessionCreationPolicy;
<%_ } _%>
<%_ if (authenticationTypes.includes('jwt')) { _%>
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import <%= packageName %>.config.security.JwtAuthenticationEntryPoint;
import <%= packageName %>.config.security.JwtAuthenticationFilter;
import <%= packageName %>.config.security.CustomUserDetailsService;
import <%= packageName %>.repositories.UserRepository;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
<%_ } _%>
<%_ if (authenticationTypes.includes('oauth2-resource')) { _%>
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
<%_ } _%>

@Configuration
@EnableWebSecurity
public class SecurityConfig {

<%_ if (authenticationTypes.includes('jwt')) { _%>
    private final UserRepository userRepository;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(UserRepository userRepository, JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.userRepository = userRepository;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }
<%_ } _%>

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            <%_ if (authenticationTypes.includes('jwt')) { _%>
            .cors(Customizer.withDefaults())
            <%_ } _%>
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/actuator/**", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                <%_ if (authenticationTypes.includes('oauth2-client')) { _%>
                .requestMatchers("/oauth2/**", "/login/**").permitAll()
                <%_ } _%>
                <%_ if (authenticationTypes.includes('jwt')) { _%>
                .requestMatchers("/api/auth/login", "/api/auth/signup", "/api/auth/refresh").permitAll()
                <%_ } _%>
                .requestMatchers("/api/admin/**").hasAuthority("ROLE_ADMIN")
                .anyRequest().authenticated()
            );

        <%_ if (authenticationTypes.includes('oauth2-resource')) { _%>
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            );
        <%_ } _%>

        <%_ if (authenticationTypes.includes('oauth2-client')) { _%>
        http.oauth2Login(oauth2 -> oauth2
            .defaultSuccessUrl("/", true)
            .failureUrl("/login?error=true")
        );
        <%_ } _%>

        <%_ if (authenticationTypes.includes('jwt') && !(authenticationTypes.includes('oauth2-resource') && authenticationTypes.includes('oauth2-client'))) { _%>

        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(ex -> ex.authenticationEntryPoint(jwtAuthenticationEntryPoint()));

        <%_ } _%>
        <%_ if (authenticationTypes.includes('jwt')) { _%>
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        <%_ } _%>
        <%_ if (authenticationTypes.length > 0) { _%>
        http.addFilterAfter(securityLogFilter(), SecurityContextHolderFilter.class);
        <%_ } _%>

        return http.build();
    }

<% if(authenticationTypes.length > 0) { _%>
    @Bean
    public SecurityLogFilter securityLogFilter() {
        return new SecurityLogFilter();
    }
<%_ } _%>

<%_ if (authenticationTypes.includes('oauth2-resource')) { _%>
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthorityPrefix("ROLE_");
        authoritiesConverter.setAuthoritiesClaimName("roles");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }
<%_ } _%>

<%_ if (authenticationTypes.includes('jwt')) { _%>
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailsService(userRepository);
    }

    @Bean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
<%_ } _%>

}