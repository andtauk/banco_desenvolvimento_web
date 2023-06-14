package br.com.api.g2.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.com.api.g2.domain.Categoria;

@Repository("categoria")
public interface CategoriaRepository extends JpaRepository<Categoria, Integer> {

	Optional<Categoria> findById(Integer id);
	
//	//Para fazer a view dentro do banco
//	@Query(value="SELECT * FROM SPAM s", nativeQuery = true)
//	public List<Categoria> spam();

}
