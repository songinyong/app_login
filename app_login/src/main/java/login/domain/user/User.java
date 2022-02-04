package login.domain.user;

import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import login.domain.BaseTimeEntity;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@Entity
@Table(name="users")
public class User extends BaseTimeEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id ;
	
	@Column()
	private String localid;
	
	@Column(nullable = false)
	private String email ;
	
	@Enumerated(EnumType.STRING)
	@Column(nullable = false)
	private Role role ;
	
	@Column()
	private String platform;
	
	@Column()
	private String password;
	
	//uid인데 uid로 작성하면 postgresql이 인식못하는 에러가 발생해서 plud로 이름을 바꿈
	@Column() 
	private String plud;
	

	@CreatedDate
	@Column(updatable = false)
	private LocalDateTime createdDate;
	
	@LastModifiedDate
	@Column()
	private LocalDateTime lastedDate;
	
	@Column()
	private String wallet;

	
	//모바일
	@Builder
	public User(String localid, String email,  Role role,  String platform, String password, String plud, String wallet) {
		this.localid  = localid ;
		this.email = email ;
		this.role = role ;
		this.platform = platform;
		this.password = password;
		this.plud = plud;
		this.wallet = wallet;
		
	}
	
	public User update(String plud) {
		this.plud = plud ;
		
		return this ;
	}
	
	public String getRoleKey() {
		return this.role.getKey();
	}
}
