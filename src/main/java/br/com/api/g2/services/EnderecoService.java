package br.com.api.g2.services;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.api.g2.domain.Endereco;
import br.com.api.g2.repositories.EnderecoRepository;

@Service
public class EnderecoService {

    @Autowired
    EnderecoRepository enderecoRepository;


    public Optional<Endereco> buscarEnderecoId(Integer id) {
        return enderecoRepository.findById(id);
    }

    public List<Endereco> buscarEnderecos() {
        return enderecoRepository.findAll();
    }

    public Endereco cadastrarEndereco(Endereco endereco) {
        return enderecoRepository.save(endereco);
    }

    public Endereco atualizarEndereco(Integer id, Endereco enderecoSolicitado) {
        Optional<Endereco> enderecoExistenteOptional = enderecoRepository.findById(id);
        if (enderecoExistenteOptional.isPresent()) {
            Endereco enderecoExistente = enderecoExistenteOptional.get();
    		enderecoExistente.setCep(enderecoSolicitado.getCep());
    		enderecoExistente.setLogradouro(enderecoSolicitado.getLogradouro());
    		enderecoExistente.setComplemento(enderecoSolicitado.getComplemento());
    		enderecoExistente.setBairro(enderecoSolicitado.getBairro());
    		enderecoExistente.setLocalidade(enderecoSolicitado.getLocalidade());
    		enderecoExistente.setUf(enderecoSolicitado.getUf());

            return enderecoRepository.save(enderecoExistente);
        } else {
            throw new IllegalArgumentException("Endereço não encontrado");
        }
    }

    public void deletarEndereco(Integer id) {
        Optional<Endereco> enderecoExistenteOptional = enderecoRepository.findById(id);
        if (enderecoExistenteOptional.isPresent()) {
            Endereco enderecoExistente = enderecoExistenteOptional.get();
            enderecoRepository.delete(enderecoExistente);
        } else {
            throw new IllegalArgumentException("Endereço não existente");
        }
    }

}
