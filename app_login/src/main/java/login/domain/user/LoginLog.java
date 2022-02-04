package login.domain.user;

import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.springframework.data.annotation.CreatedDate;

import login.domain.CreateTimeEntity;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@Entity
@Table(name="login_log")
public class LoginLog extends CreateTimeEntity{
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id ;
	
	@Column() 
	private String plud;
	
	@Column()
	private String platform;
	
    @Column()
    private String login_result;
    
	@CreatedDate
	@Column(updatable = false)
	private LocalDateTime createdDate;
	
	
	@Builder
	public LoginLog(String platform, String plud, String login_result) {
		this.plud  = plud ;		
		this.platform = platform;
        this.login_result = login_result;
		
	}

}
