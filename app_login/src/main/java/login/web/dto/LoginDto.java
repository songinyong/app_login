/*로그인 성공 실패를 기록하기 위해 사용하는 LoginLog Dto
 * */

package login.web.dto;


import login.domain.user.LoginLog;
import lombok.Builder;

import lombok.NoArgsConstructor;


@NoArgsConstructor
public class LoginDto {

	
	private String plud;
	private String platform;
	//private String wallet;
	private String login_result;

	
	@Builder
	public LoginDto(String platform, String plud, String login_result) {
		this.plud  = plud ;		
		this.platform = platform;
		this.login_result = login_result;
		//this.wallet = wallet;
		
	}
	
	public LoginLog toEntity() {
		return LoginLog.builder()
				.plud(plud)
				.platform(platform)
				.login_result(login_result)
				.build();
	}
}
