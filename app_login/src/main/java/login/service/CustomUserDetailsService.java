/*jwt filter 사용
 *배포 테스트 이후 바로 수정예정*/

package login.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import login.domain.user.CustomUserDetails;
import login.domain.user.User;
import login.domain.user.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private UserRepository usersRepository;

	@Override
	public UserDetails loadUserByUsername(String wallet) throws UsernameNotFoundException {
		User user = usersRepository.findByUser(wallet);
		if (user == null) {
			throw new UsernameNotFoundException(wallet);
		}
		CustomUserDetails userDetails = new CustomUserDetails();
		userDetails.setWallet(user.getWallet());
		return userDetails;
	}

	// uid가 있을때 true 없을때 false
	public boolean searchUid(String platfrom, String plud) {
		if (usersRepository.findBypludAndplatform(plud, platfrom).isPresent()) {

			return true;
		} else
			return false;

	}

}
