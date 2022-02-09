/*
 * token 만료되었는지를 확인하거나
 * 유효기간이 만료된 토큰을 Refresh 하는 컨트롤러 
 * 
 * */

package login.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import login.domain.token.Token;
import login.service.TokenService;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
public class TokenController {
    private final TokenService tokenService;

    @GetMapping("/user/token/expired")
    public String auth() {
        throw new RuntimeException();
    }

    @GetMapping("/user/token/refresh")
    public String refreshAuth(HttpServletRequest request, HttpServletResponse response) {
        String token = request.getHeader("Refresh");

        if (token != null && tokenService.verifyToken(token)) {
            String wallet_address = tokenService.getWalleetAddress(token);
            //user wallet_address를 통해 권한 정보 받아오도록 수정
            Token newToken = tokenService.generateToken(wallet_address, "USER");

            response.addHeader("Auth", newToken.getToken());
            response.addHeader("Refresh", newToken.getRefreshToken());
            response.setContentType("application/json;charset=UTF-8");

            return "NEW TOKEN";
        }

        throw new RuntimeException();
    }
}
