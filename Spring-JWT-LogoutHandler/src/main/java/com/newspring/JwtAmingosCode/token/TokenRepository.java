package com.newspring.JwtAmingosCode.token;

import org.hibernate.annotations.OptimisticLock;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token,Integer>
{
   // get all the tokens from the tken table which are not yet expired or revoked and which are valid
   @Query(value=""" 
select  t from Token t inner join User u on t.user.id = u.id where u.id= :userId and (t.expired=false or t.revoked=false )
""")
   List<Token> findAllValidTokensByUser(Integer userId);


   Optional<Token> findByToken(String token);
}
