package br.com.api.g2.domain;


import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Entity
@Table(name="item_pedido")
public class ItemPedido {

	@Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column(name= "item_cd_id")
	@Schema(requiredMode = Schema.RequiredMode.REQUIRED, defaultValue= "Identificador unico do item pedido")
	private Integer itemId;
	
	@Column(name="item_int_qnt")
	@NotNull(message="A quantidade do item é obrigatória.")
	@Min(value=1, message="A quantidade do item deve ser maior que zero.")
	private Integer quantidade;
	
	
	@Column(name="item_nm_valor_final")
	@NotNull(message="O valor final do item é obrigatório.")
	@DecimalMin(value="0.0", inclusive=true, message="O valor final do item deve ser igual ou maior que zero.")
	private Double valorFinal;
	
	 //Um item podem estar em vários pedido
	 @ManyToOne
	 @JoinColumn(name = "fk_ped_cd_id")
	 private Pedido pedido;

	 //Muitos itens de um produto
	 @ManyToOne
	 @JoinColumn(name = "fk_prod_cd_id")
	 private Produto produto;
	
	

	public ItemPedido() {
	
	}



	public ItemPedido(Integer itemId, Integer quantidade, Double valorFinal, Pedido pedido, Produto produto) {
		this.quantidade = quantidade;
		this.valorFinal = valorFinal;
		this.pedido = pedido;
		this.produto = produto;
	}



	public Integer getItemId() {
		return itemId;
	}



	public void setItemId(Integer itemId) {
		this.itemId = itemId;
	}



	public Integer getQuantidade() {
		return quantidade;
	}



	public void setQuantidade(Integer quantidade) {
		this.quantidade = quantidade;
	}



	public Double getValorFinal() {
		return valorFinal;
	}



	public void setValorFinal(Double valorFinal) {
		this.valorFinal = valorFinal;
	}



	public Pedido getPedido() {
		return pedido;
	}



	public void setPedido(Pedido pedido) {
		this.pedido = pedido;
	}



	public Produto getProduto() {
		return produto;
	}



	public void setProduto(Produto produto) {
		this.produto = produto;
	}
	
}
