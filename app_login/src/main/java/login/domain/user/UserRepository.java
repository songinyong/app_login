package login.domain.user;

import java.util.List;
import java.util.Optional ;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, Long>{

	Optional<User> findByEmail(String email);
	
	
	@Query(value="SELECT u FROM users u WHERE u.wallet =?1 ", nativeQuery = true)
	User findByUser(String wallet);
	
	//@Query(value="SELECT u FROM users u WHERE u.plud =:plud and u.platform = :platform", nativeQuery = true)
	//Optional<User> findByplud(@Param("plud") String plud, @Param("platform") String platform);
	@Query(value="SELECT * FROM users u WHERE u.plud =?1 and u.platform = ?2", nativeQuery = true)
	Optional<User> findBypludAndplatform(String plud, String platform );
	
	
}
