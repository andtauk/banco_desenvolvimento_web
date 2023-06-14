package br.com.api.g2.repositories;



import org.springframework.data.jpa.repository.JpaRepository;

import br.com.api.g2.domain.Usuario;

public interface UsuarioRepository extends JpaRepository<Usuario, Integer> {

	

}
