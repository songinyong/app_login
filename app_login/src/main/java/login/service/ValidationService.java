/*
 * 앱으로부터 건네받은 access_token으로 uid값을 확인하는 기능(회원가입, 로그인)
 * 
 * */


package login.service;

import java.util.Optional;

import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import login.domain.token.Token;
import login.domain.user.LoginRepository;
import login.domain.user.User;
import login.domain.user.UserRepository;
import login.web.dto.LoginDto;

@Service
public class ValidationService {

	
	@Autowired
	CustomUserDetailsService cuds ;
	@Autowired
	TokenService tokenService;
	
	@Autowired
	private LoginRepository loginRepository;
	
	@Autowired
	private UserRepository usersRepository;

	
//토큰 검증 과정
public ResponseEntity<JSONObject> token_vali(String platform, String access_token, String plud) {

	//uid와 platform으로 일치하는 wallet_address 값 검색
	Optional<User> user =usersRepository.findBypludAndplatform(plud, platform);
	
    	if(user.isPresent()) {
    		System.out.println("uid 검색 성공");
    		LoginDto ldto = new LoginDto(platform,plud, "success");
    		loginRepository.save(ldto.toEntity());
    	
    		return tokenValiCheck(access_token, user.get().getWallet()) ;
    	
    	}
    	else {
    		System.out.println("uid 검색 실패");
    		LoginDto ldto = new LoginDto(platform,plud, "failed uid");
    		loginRepository.save(ldto.toEntity());
    		
            return new ResponseEntity<JSONObject>(loginResult("false", "", "failed searching uid"), HttpStatus.NOT_FOUND);
    		
    	}
    }





public JSONObject loginResult(String result ,String toke  ,String error) {
	JSONObject resultObj = new JSONObject();
	resultObj.put("result",result);
	resultObj.put("error",error);
	resultObj.put("token",toke);
	
	
	return resultObj ;
}

//로그인 성공시 jwt 토큰 발급
private ResponseEntity<JSONObject> tokenValiCheck(String access_token, String wallet_address) {
	RestTemplate rt = new RestTemplate();
	try {
		
		ResponseEntity<String> response = rt.getForEntity("https://www.googleapis.com/oauth2/v1/userinfo?access_token="+access_token, String.class);
	}
	catch (Exception e) {
		return new ResponseEntity<JSONObject>(loginResult("false", "", "token validation error"), HttpStatus.NOT_FOUND);
	}
	Token jwttoken = tokenService.generateToken(wallet_address, "USER");  
	
	return new ResponseEntity<JSONObject>(loginResult("true", jwttoken.getToken(), ""), HttpStatus.ACCEPTED);
}

//회원가입
public String tokenValiCheck(String access_token) {
	RestTemplate rt = new RestTemplate();
	try {
		ResponseEntity<JSONObject> response = rt.getForEntity("https://www.googleapis.com/oauth2/v1/userinfo?access_token="+access_token, JSONObject.class);
	    return (String) response.getBody().get("id") ;
	}
	catch (Exception e) {
		return "false";
		
	}
}

}
