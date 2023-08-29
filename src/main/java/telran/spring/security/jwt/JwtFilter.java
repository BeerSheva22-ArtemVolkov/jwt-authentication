package telran.spring.security.jwt;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtFilter extends OncePerRequestFilter {

	private static final String BEARER = "Bearer "; 
	final JwtUtil jwtUtil;
	final UserDetailsService userDetailsService; // берется из accounting-management => AccountingConfiguration

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		log.warn("JwtFilter - doFilterInternal");
		String jwt = getJwt(request);
		log.trace("jwt from header is {}", jwt == null ? "null" : jwt);
		if (jwt != null) {
			try {
				String username = jwtUtil.extractUsername(jwt);
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);
				log.trace("extracted username is {}", username);
				if (userDetails == null || !userDetails.isAccountNonExpired()) {
					throw new UsernameNotFoundException(username);
				}
				UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				// Устанавливается аутентификация в контексте безопасности приложения, те
				// пользователь успешно прошел аутентификацию и теперь имеет правильные учетные
				// данные.
				// Строится Sequrity Context
				SecurityContextHolder.getContext().setAuthentication(authenticationToken);
				log.trace("security context is established");
			} catch (Throwable e) {
				e.printStackTrace();
			}
		}

		filterChain.doFilter(request, response);

	}

	private String getJwt(HttpServletRequest request) {

		String authHeader = request.getHeader("Authorization");
		String res = null;

		if (authHeader != null && authHeader.startsWith(BEARER)) {
			res = authHeader.substring(BEARER.length());
		}

		return res;
	}

}
