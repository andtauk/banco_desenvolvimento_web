package br.com.api.g2.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.com.api.g2.domain.Endereco;

@Repository("endereco")
public interface EnderecoRepository extends JpaRepository<Endereco, Integer> {

	Optional<Endereco> findById(Integer id);

}
