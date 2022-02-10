/*
 * 토큰 발급을 담당하는 서비스
 * */

package login.service;

import java.util.Base64;
import java.util.Date;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import login.domain.token.Token;
import login.domain.user.User;
import login.domain.user.UserRepository;

@Service
public class TokenService {
	
	
	@Value("${jwt.secret}")
	private String secretKey ;
	
	@Autowired
	private UserRepository usersRepository;
	
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
	
	
	
	
	
	
	//토큰의 유효성 확인 및 토큰의 wallet_address와 api를 호출대상 wallet_address가 일치하는지 비교 하는 코드
	//다른 서비스들에서 토큰 검증용으로 사용
	public String getWalleetAddress(String token) {
		String wallet_address = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
		
		if(searchWalletAddress(wallet_address)) return wallet_address ;
		else return null ; 
	}
	
	private boolean searchWalletAddress(String wallet_address) {
		User user = usersRepository.findByUser(wallet_address);
		if (user == null) {
			return false ;
		}
		else {
			return true ;
		}
	}

	
	
}
