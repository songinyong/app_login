/*현재 util 기능은 클라우드 게이트웨이가 담당하나 백업요으로 남겨만둠
 * 배포 서비스 완료되고 코드 리팩토링이 완료되면 삭제 예정
 * 후에 웹 로그인으로까지 확장되면 사용예정*/

package login.config.auth.jwt;

import java.io.Serializable;
import java.util.Date;

import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class JwtTokenUtil implements Serializable {

	private static final long serialVersionUID = 2750185165626007488L;
	

	@Value("${jwt.secret}")
	private String secret;

	//wallet 주
	public String getWalletFromToken(String token) {
		return getClaimFromToken(token, Claims::getSubject);
	}

	public Date getIssuedAtDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getIssuedAt);
	}

	public Date getExpirationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}

	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	private Boolean ignoreTokenExpiration(String token) {
		
		return false;
	}


	public Boolean canTokenBeRefreshed(String token) {
		return (!isTokenExpired(token) || ignoreTokenExpiration(token));
	}

	/*
	 * UserDetails 메소도명은 name이여도 실제 비교는 wallet을 기준으로함
	 * */
	public Boolean validateToken(String token, UserDetails userDetails) {
		final String userWallet = getWalletFromToken(token);
		return (userWallet.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
	
	  public String resolveToken(HttpServletRequest request) {
		    
		    return request.getHeader("X-AUTH-TOKEN");
		  }
}
