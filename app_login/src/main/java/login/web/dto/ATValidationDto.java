/*앱에서 넘어온 로근인 정보를 처리하는 Dto*/
package login.web.dto;

import java.util.Map;

import org.codehaus.jackson.JsonParser;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class ATValidationDto {

	Map<String, Object> user ;
	private String access_token ;
	private long uid ;
	private String platform ;
	
	@Builder
	public ATValidationDto(String platform, Map<String, Object> user) {
		
		this.access_token = (String) user.get("token") ;
		this.uid = (Long) user.get("uid") ;
		
		
	}
	

	
}
