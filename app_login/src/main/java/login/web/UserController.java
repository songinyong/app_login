/*
 * 로그인 관련 처리를 하는 컨트롤러
 * 앱에서 액세스 토큰을 받은뒤에 토큰의 유효성 확인후 jwt 토큰을 넘겨주는 부분과
 * 웹에서 로그인 단계부터 토큰 제공까지 처리하는 부분 두개로 나뉨
 * 
 * 12-02 register 및 validation 기존 규약대로 응답값 맞추고 테스트 진행
 * 21.12.03 플랫폼 따라서 한글 문구가 깨지는 경우가 있어서 응답 메시지는 전부 한글로 통일
 * */

package login.web;

/*
 * 로그인과 회원가입 진행
 * 22.02.04 웹 로그인과 앱 로그인 분리
 * 
 * */

import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


import login.service.RegisterService;
import login.service.ValidationService;
import login.web.dto.ATValidationDto;
import login.web.dto.RegisterDto;
import lombok.RequiredArgsConstructor;
@RequiredArgsConstructor
@Controller
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class UserController {

	
	@Autowired
	RegisterService resService ;

	@Autowired
	ValidationService valiService;
	
	@Value("${spring.security.oauth2.client.registration.google.client-id}")
	private String client_id ;
	
	@Value("${spring.security.oauth2.client.registration.google.client-secret}")
	private String client_secret ;
	

   
    //앱에서 access 토큰을 받은뒤에 토큰의 유효성을 확인후 jwt토큰을 발급해준다.
    @PostMapping("/user/validation")
    public ResponseEntity<JSONObject> token_vali(@RequestBody ATValidationDto atv) {
    	 	

    	//String token = "Bearer "+atv.getUser().get("token") ;
    	String plud = String.valueOf(atv.getUser().get("id"));
    	System.out.println(plud);
    	return valiService.token_vali(atv.getPlatform(), (String) atv.getUser().get("token"), plud);
      	
    }
    //회원가입 요청 처리 
    @PostMapping("/user/register")
    public ResponseEntity<JSONObject> registerUser(@RequestBody RegisterDto rdto) {
    	System.out.println(rdto.getUser_info().get("token"));
    	System.out.println(valiService.tokenValiCheck((String) rdto.getUser_info().get("token"))+"vali상태 체크");
    	
    	System.out.println(resService.getWallet());
    	
    	if(!valiService.tokenValiCheck((String) rdto.getUser_info().get("token")).equals("false")) {
    		rdto.setPlud(valiService.tokenValiCheck((String) rdto.getUser_info().get("token")));
    		rdto.setWallet(resService.getWallet());
        	System.out.println(rdto.getPlud());	
        	
        	if(resService.saveOrUpdate(rdto)) {
        		return new ResponseEntity<JSONObject>(resService.registerResult("true", resService.getWallet()), HttpStatus.CREATED);
        	}
        	//같은 플랫폼 서비스의 uid가 이미 있어 삽입불가능할때
        	else {
        		return new ResponseEntity<JSONObject>(resService.registerResult("false", ""), HttpStatus.NOT_ACCEPTABLE);
        	}
        	//access_token 잘못되었을때
    	} else {
    		return new ResponseEntity<JSONObject>(resService.registerResult("false: incorrect token", ""), HttpStatus.NOT_ACCEPTABLE);
    	}
    	    	
    }
  
}
