/*
 * 회원가입 요청 서비스 담당 클래스
 * 
 * save 메소드로 기존에 가입된 계정인지 파악하고 계정 없을시 true 계정 있을시 false 결과 전송 
 * registerResult 입력된 파라미터 값들을 json형태로 만들어 반환하는 메서드 
 * */


package login.service;

import java.util.NoSuchElementException;

import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import login.domain.user.UserRepository;
import login.web.dto.RegisterDto;

@Service
public class RegisterService  {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	CustomUserDetailsService cuds ;
	
	
	/*
	 * 회원가입 진행 과정
	 * db에 없는 uid인지 체크
	 * db에 uid가 있다면 false 리턴
	 *  
	 * */
    public Boolean saveOrUpdate(RegisterDto rdto) {
        try {
        	
    	if (cuds.searchUid(rdto.getPlatform(),rdto.getPlud())) {
    		System.out.println("존재하는 uid");
    		return false ;
    	} else {
    		userRepository.save(rdto.toEntity());
    		return true;	
    	 }
    	
    	 }
        catch (NoSuchElementException e){
        	
    		return false ;
        }
    	
    }
    /*
     * 결과를 json 형태로 바꿔주는 메서드
     * 리팩토링 진행 예정
     * */
	public JSONObject registerResult(String result, String wallet ) {
		JSONObject resultObj = new JSONObject();
		resultObj.put("result",result);
		resultObj.put("wallet address",wallet);
		
		return resultObj ;
	}
	
	/*
	 * 블록체인 서비스로부터 지갑 정보를 받아옴
	 * */
	public String getWallet() {
		
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		HttpHeaders headers = new HttpHeaders();
		headers.add("Content-type", "application/json;charset=utf-8");
		
		HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers); 
		RestTemplate rt = new RestTemplate();
		
		JSONObject result =rt.postForObject("http://54.180.114.232:5555/chain/walletCreate", entity, JSONObject.class);
		
		return (String)result.get("wallet_address");
		
	}
}
