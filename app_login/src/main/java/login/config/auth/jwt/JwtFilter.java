/*jwt 토큰 유효성 확인및 등록된 회원인지 확인하는 클래스
 * 로그인 프로세스 설계가 바뀐이후로 역시 배포 테스트 직후 다시 수정할 예정
 * 참고용으로만 남겨저 있고 현재 jwt 유효성 체크는 게이트웨이를 통해 진행됨
 * */

package login.config.auth.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import login.service.CustomUserDetailsService;
import login.service.TokenService;

@Component
public class JwtFilter extends OncePerRequestFilter {
@Autowired
private JwtTokenUtil jwtUtil;
@Autowired
private CustomUserDetailsService service;

@Override
protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
	String authorizationHeader = httpServletRequest.getHeader("Authorization");
    String token = null;
    String userWallet = null;
    
    //jwt 토큰에서 Bearer 이라는 단어 제거 
    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
        token = authorizationHeader.substring(7);
        userWallet = jwtUtil.getWalletFromToken(token);
    }
    
    //jwt token에 들어있는 wallet이 존재하는지 확인하고 유효기간 체크
    if (userWallet != null && SecurityContextHolder.getContext().getAuthentication() == null) {
        UserDetails userDetails = service.loadUserByUsername(userWallet);
    
        if (jwtUtil.validateToken(token, userDetails)) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        usernamePasswordAuthenticationToken
               .setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        }
    
    }
    filterChain.doFilter(httpServletRequest, httpServletResponse);
}

}

