/*
 * jwt토큰 filter에서 사용하는 domain
 * UserDetails을 구현하지 않는 새로운 도메인으로 구현다도록 리팩토링 예정
 * */

package login.domain.user;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Getter;

@Getter
public class CustomUserDetails implements UserDetails {
    
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String id;
    private String PASSWORD;
    private String AUTHORITY;
    private boolean ENABLED;
    private String Wallet ;
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        ArrayList<GrantedAuthority> auth = new ArrayList<GrantedAuthority>();
        auth.add(new SimpleGrantedAuthority(AUTHORITY));
        return auth;
    }
 
    @Override
    public String getPassword() {
        return PASSWORD;
    }
 
    //UserDetails 구현을 위해 메소드명은 유지하되 return은 Wallet 주소
    @Override
    public String getUsername() {
        return Wallet;
    }
 
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
 
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
 
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
 
    @Override
    public boolean isEnabled() {
        return ENABLED;
    }
    
 
    public void setWallet(String wallet) {
    	Wallet = wallet;
    }




 
}


