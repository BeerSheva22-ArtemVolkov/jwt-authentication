package telran.spring.security.jwt;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import telran.spring.security.RolesConfiguration;
import telran.spring.security.SecurityExceptionsHandler;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class JwtSecurityConfiguration {

	final JwtFilter jwtFilter; 
	final RolesConfiguration rolesConfiguration;
	final SecurityExceptionsHandler securityExceptionsHandler;

	@Bean
	@Order(Ordered.LOWEST_PRECEDENCE)
	SecurityFilterChain configure(HttpSecurity http) throws Exception { // SecurityFilterChain - запросы приходят на
																		// него в первую очередь
		log.warn("JwtSecurityConfiguration - configure");
		http.csrf(custom -> custom.disable())
				.exceptionHandling(custom -> custom.accessDeniedHandler(securityExceptionsHandler)
						.authenticationEntryPoint(securityExceptionsHandler))
				.authorizeHttpRequests(custom -> custom.requestMatchers("/login").permitAll().requestMatchers(HttpMethod.OPTIONS).permitAll());
//						.requestMatchers(HttpMethod.GET).authenticated().anyRequest().hasRole("ADMIN"))
		rolesConfiguration.configure(http);
		return http.httpBasic(Customizer.withDefaults())
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class).build();
	}

}
