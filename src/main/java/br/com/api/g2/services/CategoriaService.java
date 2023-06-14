package br.com.api.g2.services;


import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.api.g2.domain.Categoria;
import br.com.api.g2.repositories.CategoriaRepository;


@Service
public class CategoriaService {

    @Autowired
    CategoriaRepository categoriaRepository;


    public Optional<Categoria> buscarCategoriaId(Integer id) {
        return categoriaRepository.findById(id);
    }

    public List<Categoria> buscarCategorias(Pageable page) {
    	return categoriaRepository.findAll(page).getContent();
    }
    
//  //pra view do banco de dados
//  public List<Categoria> spam() {
//  	return categoriaRepository.spam();
//    }

    public Categoria cadastrarCategoria(Categoria categoria) {
        return categoriaRepository.save(categoria);
    }

    public Categoria atualizarCategoria(Integer id, Categoria categoriaSolicitada) {
        Optional<Categoria> categoriaExistenteOptional = categoriaRepository.findById(id);
        if (categoriaExistenteOptional.isPresent()) {
            Categoria categoriaExistente = categoriaExistenteOptional.get();
            categoriaExistente.setNome(categoriaSolicitada.getNome());
            categoriaExistente.setDescricao(categoriaSolicitada.getDescricao());

            return categoriaRepository.save(categoriaExistente);
        } else {
            throw new IllegalArgumentException("Categoria não encontrada");
        }
    }

    public void deletarCategoria(Integer id) {
        Optional<Categoria> categoriaExistenteOptional = categoriaRepository.findById(id);
        if (categoriaExistenteOptional.isPresent()) {
            Categoria categoriaExistente = categoriaExistenteOptional.get();
            categoriaRepository.delete(categoriaExistente);
        } else {
            throw new IllegalArgumentException("Categoria não existente");
        }
    }
}
