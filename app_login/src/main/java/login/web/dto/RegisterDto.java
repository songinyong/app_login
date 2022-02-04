/*회원가입 요청을 담당하는 dto 객체
 * 
 * 최종 수정일 21.12.03 
 * user_id 통일성 위해 수정
 * */

package login.web.dto;


import java.util.Map;

import login.domain.user.Role;
import login.domain.user.User;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@NoArgsConstructor
public class RegisterDto {
	    private Map<String, Object> user_info ;
	    private String user_id;
	    private String email;
	    private String plud;
	    private String platform;
	    private String password;
	    private String wallet;
	    
		@Builder
		public RegisterDto(String platform, Map<String, Object> user_info) {
		    this.platform = platform ;
		    this.user_info = user_info;
		}
	    
	    public User toEntity(){
	    	
	    	email = (String) user_info.get("email");
	    	user_id = (String) user_info.get("user_id");
	    	password = (String) user_info.get("password");
	    	
	        return User.builder().password(password)
	                .platform(platform)
	                .email(email)
	                .localid(user_id)
	                .plud(plud)
	                .role(Role.GUEST)
	                .wallet(wallet)
	                .build();
	    }
	    
	   
}
