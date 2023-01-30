package com.example.eindopdrachtbackendv1.Security;

import com.example.eindopdrachtbackendv1.Repositories.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig  {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    public SecurityConfig(JwtService service, UserRepository userRepos) {
        this.jwtService = service;
        this.userRepository = userRepos;
    }

    @Bean
    public AuthenticationManager authManager(HttpSecurity http, PasswordEncoder encoder, UserDetailsService udService) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(udService)
                .passwordEncoder(encoder)
                .and()
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new MyUserDetailsService(this.userRepository);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .httpBasic().disable()
                .cors().and()
                .authorizeRequests()

                .antMatchers(HttpMethod.DELETE, "/**").hasRole("ADMIN")

                .antMatchers(HttpMethod.POST, "/auth/**").permitAll()
                .antMatchers(HttpMethod.GET, "/auth/**").permitAll()
                .antMatchers(HttpMethod.PUT, "/auth/**").permitAll()

                .antMatchers(HttpMethod.POST, "/users/**").permitAll()
                .antMatchers(HttpMethod.GET, "/users/**").permitAll()
                .antMatchers(HttpMethod.PUT,"/users/**").permitAll()


                .antMatchers(HttpMethod.POST, "/uploads/**").permitAll()
                .antMatchers(HttpMethod.GET, "/uploads/**").permitAll()
                .antMatchers(HttpMethod.PUT,"/uploads/**").permitAll()

                .antMatchers(HttpMethod.POST, "/fishingspots/**").permitAll()
                .antMatchers(HttpMethod.GET, "/fishingspots/**").permitAll()
                .antMatchers(HttpMethod.PUT,"/fishingspots/**").permitAll()

                .antMatchers(HttpMethod.POST, "/ratings/**").permitAll()
                .antMatchers(HttpMethod.GET, "/ratings/**").permitAll()
                .antMatchers(HttpMethod.PUT,"/ratings/**").permitAll()

                .antMatchers(HttpMethod.POST, "/gears/**").permitAll()
                .antMatchers(HttpMethod.GET, "/gears/**").permitAll()
                .antMatchers(HttpMethod.PUT,"/gears/**").permitAll()

                .antMatchers(HttpMethod.POST, "/locations/**").permitAll()
                .antMatchers(HttpMethod.GET, "/locations/**").permitAll()
                .antMatchers(HttpMethod.PUT,"/locations/**").permitAll()

                .antMatchers(HttpMethod.PUT,"/single/**").permitAll()
                .antMatchers(HttpMethod.PUT,"/download/**").permitAll()



                .antMatchers("/secret").hasAuthority("ADMIN")
                .antMatchers("/**").hasAnyAuthority("USER", "ADMIN")

                .and()
                .addFilterBefore(new JwtRequestFilter(jwtService, userDetailsService()), UsernamePasswordAuthenticationFilter.class)
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        return http.build();
    }
}

//
