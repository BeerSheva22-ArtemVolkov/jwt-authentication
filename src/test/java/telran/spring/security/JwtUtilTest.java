package telran.spring.security;

import static org.junit.jupiter.api.Assertions.*;
import org.assertj.core.util.Arrays;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.User;

import io.jsonwebtoken.ExpiredJwtException;
import telran.spring.security.jwt.JwtUtil;

@SpringBootTest(classes = {JwtUtil.class})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class JwtUtilTest {

	@Autowired
	JwtUtil jwtUtil;
	static String jwt;
	static final String USER_NAME = "user";
	static String[] expectedRoleStrings = { "ADMIN" };

	@Test
	@Order(1)
	void creationJwt() {
		jwt = jwtUtil.createToken(User.withUsername(USER_NAME).password("xxxxx").roles("ADMIN").build());
	}

	@Test
	@Order(2)
	void extractUsernameTest() {
		assertEquals(USER_NAME, jwtUtil.extractUsername(jwt));
	}

	@Test
	@Order(3)
	void extractRolesTest() {
		assertIterableEquals(Arrays.asList(expectedRoleStrings), jwtUtil.extractRoles(jwt));
	}

	@Test
	@Order(4)
	void expirationTest() throws InterruptedException {
		Thread.sleep(3000);
		assertThrowsExactly(ExpiredJwtException.class, () -> jwtUtil.extractUsername(jwt));
	}

}
