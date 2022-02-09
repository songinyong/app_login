/*
 * 토큰 발급을 담당하는 서비스
 * */

package login.service;

import java.util.Base64;
import java.util.Date;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import login.domain.token.Token;

@Service
public class TokenService {
	
	
	@Value("${jwt.secret}")
	private String secretKey ;
	
	@PostConstruct
	protected void init() {
		secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
	
	}
	
	public String getJwtSigningKey() {
        return secretKey;
    }
	
	//토큰 생성 코드
	public Token generateToken(String wallet_address, String role) {
		long tokenPeriod = 1000L * 60L * 15L; // 토큰 유효시간 
		long refreshPeriod = 1000L * 60L * 60L *24L * 30L ; //refresh 토큰 유효시간
		
		Claims claims = Jwts.claims().setSubject(wallet_address);
		claims.put("role", role);
		
		Date now = new Date();
		return new Token(
				//jwt 토큰 생성
				Jwts.builder().setClaims(claims).setIssuedAt(now)
				.setExpiration(new Date(now.getTime()+ tokenPeriod))
				.signWith(SignatureAlgorithm.HS256, secretKey).compact(),
				
				//refresh 토큰 생성
				Jwts.builder()
				.setClaims(claims)
				.setIssuedAt(now)
				.setExpiration(new Date(now.getTime()+refreshPeriod))
				.signWith(SignatureAlgorithm.HS256, secretKey)
				.compact()
				);
				
	}
	
	//토큰 유효기간 확인
	public boolean verifyToken(String token) {
		try {
			Jws<Claims> claims = Jwts.parser()
					.setSigningKey(secretKey)
					.parseClaimsJws(token);
			return claims.getBody()
					.getExpiration()
					.after(new Date());
		} catch (Exception e) {
			return false;
		}
	}
	
	public String getWalleetAddress(String token) {
		return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
	}
	
	
}
