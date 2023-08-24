package space.bum.c11_ex1.config;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class SecurityConfig {
	@Bean
	@Order(1)
	SecurityFilterChain asSecurityFilterChain(HttpSecurity http)
			throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
				.oidc(Customizer.withDefaults());
		
		http.exceptionHandling(e ->
				e.authenticationEntryPoint(
						new LoginUrlAuthenticationEntryPoint("/login")
						)
				);
		
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
	
	@Bean
	UserDetailsService userDetailsService() {
		var user = User.withUsername("park")
				.password("1234")
				.authorities("read").build();
		
		return new InMemoryUserDetailsManager(user);
	}
	
	@SuppressWarnings("deprecation")
	@Bean
	PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	@Bean
	RegisteredClientRepository registeredClientRepository() {
		var r1 = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client").clientSecret("secret").scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.redirectUri("https://springone.io/authorized")
				.clientAuthenticationMethod(
						ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.build();

		return new InMemoryRegisteredClientRepository(r1);
	}
	
	@Bean
	AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
				.build();
	}
	
	@Bean
	JWKSource<SecurityContext> jwkSource() 
															throws NoSuchAlgorithmException {
		KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
		kg.initialize(2048);
		KeyPair kp = kg.generateKeyPair();
		
		RSAPublicKey pubKey = (RSAPublicKey) kp.getPublic();
		RSAPrivateKey priKey = (RSAPrivateKey) kp.getPrivate();
		
		RSAKey key = new RSAKey.Builder(pubKey)
				.privateKey(priKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		
		JWKSet set = new JWKSet(key);
		return new ImmutableJWKSet<SecurityContext>(set);
	}
	// @formatter:on
}
