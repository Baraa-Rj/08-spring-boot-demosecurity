package com.luv2code.springboot.demosecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class DemoSecurityConfig {

    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource) {
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.setUsersByUsernameQuery(
                "select * from members where user_id=?"
        );
        jdbcUserDetailsManager.setAuthoritiesByUsernameQuery(
                "select * from roles where user_id=?"
        );

        return jdbcUserDetailsManager;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(configurer -> {
            configurer.
                    requestMatchers("/").hasRole("EMPLOYEE").
                    requestMatchers("/leaders/**").hasRole("Manager").
                    requestMatchers("/systems/**").hasRole("Admin").
                    anyRequest().authenticated();
        }).exceptionHandling(configurer -> {
            configurer.accessDeniedPage("/access-denied");
        }).formLogin(form -> {
            form.loginPage("/showMyLoginPage").loginProcessingUrl("/authenticateTheUser").permitAll();
        }).logout(LogoutConfigurer::permitAll);
        return http.build();
    }
     /*   @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        UserDetails john = User.builder().username("john").password("{noop}test123").roles("EMPLOYEE").build();
        UserDetails mary = User.builder().username("mary").password("{noop}test123").roles("EMPLOYEE", "Manager").build();
        UserDetails susan = User.builder().username("susan").password("{noop}test123").roles("EMPLOYEE", "Manager", "Admin").build();
        return new InMemoryUserDetailsManager(john, mary, susan);
    }*/
}
