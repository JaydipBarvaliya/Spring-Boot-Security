package io.javabrains.springbootsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    public UserDetailsService users() {

        UserDetails user =  User.builder()
                                .username("user")
                                .password("user")
                                .roles("USER")
                                .build();

        UserDetails admin = User.builder()
                                .username("admin")
                                .password("admin")
                                .roles("USER", "ADMIN")
                                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {

        return NoOpPasswordEncoder.getInstance();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(auth ->
                                        auth.requestMatchers("/admin").hasRole("ADMIN")
                                            .requestMatchers("/user").hasAnyRole("USER", "ADMIN")
                                            .requestMatchers("/").permitAll()
                                            ).formLogin();
        return http.build();
    }
}
