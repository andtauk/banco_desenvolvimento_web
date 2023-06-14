package br.com.api.g2.services;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.api.g2.domain.ItemPedido;
import br.com.api.g2.repositories.ItemPedidoRepository;

@Service
public class ItemPedidoService {

    @Autowired
    ItemPedidoRepository itemPedidoRepository;


    public Optional<ItemPedido> buscarItemPedidoId(Integer id) {
        return itemPedidoRepository.findById(id);
    }

    public List<ItemPedido> buscarItensPedido() {
        return itemPedidoRepository.findAll();
    }

    public ItemPedido cadastrarItemPedido(ItemPedido itemPedido) {
        return itemPedidoRepository.save(itemPedido);
    }

    public ItemPedido atualizarItemPedido(Integer id, ItemPedido itemPedidoSolicitado) {
        Optional<ItemPedido> itemPedidoExistenteOptional = itemPedidoRepository.findById(id);
        if (itemPedidoExistenteOptional.isPresent()) {
            ItemPedido itemPedidoExistente = itemPedidoExistenteOptional.get();
            itemPedidoExistente.setQuantidade(itemPedidoSolicitado.getQuantidade());
            itemPedidoExistente.setValorFinal(itemPedidoSolicitado.getValorFinal());

            return itemPedidoRepository.save(itemPedidoExistente);
        } else {
            throw new IllegalArgumentException("Item do pedido não encontrado");
        }
    }

    public void deletarItemPedido(Integer id) {
        Optional<ItemPedido> itemPedidoExistenteOptional = itemPedidoRepository.findById(id);
        if (itemPedidoExistenteOptional.isPresent()) {
            ItemPedido itemPedidoExistente = itemPedidoExistenteOptional.get();
            itemPedidoRepository.delete(itemPedidoExistente);
        } else {
            throw new IllegalArgumentException("Item do pedido não existente");
        }
    }

}
