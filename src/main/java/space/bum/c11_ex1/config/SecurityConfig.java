package space.bum.c11_ex1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
	@Bean
	@Order(1)
	SecurityFilterChain asSecurityFilterChain(HttpSecurity http)
			throws Exception {
		return http.build();
	}

	// @formatter:off
	@Bean
	@Order(2)
	SecurityFilterChain appSecurityFilterChain(HttpSecurity http)
			throws Exception {
		http.formLogin().and()
			.authorizeHttpRequests().anyRequest().authenticated();

		return http.build();
	}
	// @formatter:on
}
