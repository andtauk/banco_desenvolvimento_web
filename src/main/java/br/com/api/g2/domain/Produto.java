package br.com.api.g2.domain;

import java.time.LocalDate;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonFormat;

import br.com.api.g2.enums.CategoriaEnum;
import br.com.api.g2.security.domain.User;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Entity
@Table(name="produto")
public class Produto {

	@Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column(name= "prod_cd_id")
	@Schema(requiredMode = Schema.RequiredMode.REQUIRED, defaultValue= "Identificador unico do produto")
	private Integer produtoId;
	
	@Column(name="prod_tx_nome")
	@NotNull(message="O nome do produto é obrigatório.")
	@NotBlank(message="O nome do produto é obrigatório.")
	private String nome;
	
	@Column(name="prod_tx_descricao")
	@NotNull(message="A descrição do produto é obrigatória.")
	@NotBlank(message="A descrição do produto é obrigatória.")
	private String descricao;
	
	@Column(name="prod_int_qnt_estoque")
	@NotNull(message="A quantidade em estoque é obrigatória.")
	@Min(value=0, message="A quantidade em estoque não pode ser negativa.")
	private Integer quantidadeEstoque;
	
	//adiciona a data e hora
	@Temporal(TemporalType.DATE)
    @JsonFormat(pattern = "dd/MM/yyyy")
	@Column(name = "prod_dt_fabricacao", nullable = false)
	private LocalDate data;
		
	@Column(name="prod_nm_valor_unitario")
	@NotNull(message="O valor unitário do produto é obrigatório.")
	@DecimalMin(value="0.0", inclusive=true, message="O valor unitário do produto deve ser igual ou maior que zero.")
	private Double valorUnitario;
	
	
	private String url;


	//Uma categoria tem muitos produtos
	@ManyToOne
	@JoinColumn(name="fk_cat_cd_id")
	private Categoria categoria;
	
	//Um usuario tem mts produtos
	@ManyToOne
	@JoinColumn(name="fk_usu_cd_id")
	private Usuario usuario;
	
	//Um produto pode estar em varios itens
	@OneToMany(mappedBy = "produto")
    private List<ItemPedido> itensPedido;
	
	@OneToOne
	@JoinColumn(name = "fk_id")
	private User user;
	
	public Produto() {

	}

	public Produto(Integer produtoId, String nome, String descricao, Integer quantidadeEstoque, LocalDate data,
			Double valorUnitario, String url, Categoria categoria) {
		this.produtoId = produtoId;
		this.nome = nome;
		this.descricao = descricao;
		this.quantidadeEstoque = quantidadeEstoque;
		this.data = data;
		this.valorUnitario = valorUnitario;
		this.url = url;
		this.categoria = categoria;
	}
	
	

	public Categoria getCategoria() {
		return categoria;
	}

	public void setCategoria(Categoria categoria) {
		this.categoria = categoria;
	}

	public  String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public Integer getProdutoId() {
		return produtoId;
	}

	public void setProdutoId(Integer produtoId) {
		this.produtoId = produtoId;
	}

	public String getNome() {
		return nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}

	public String getDescricao() {
		return descricao;
	}

	public void setDescricao(String descricao) {
		this.descricao = descricao;
	}

	public Integer getQuantidadeEstoque() {
		return quantidadeEstoque;
	}

	public void setQuantidadeEstoque(Integer quantidadeEstoque) {
		this.quantidadeEstoque = quantidadeEstoque;
	}

	public LocalDate getData() {
		return data;
	}

	public void setData(LocalDate data) {
		this.data = data;
	}

	public Double getValorUnitario() {
		return valorUnitario;
	}

	public void setValorUnitario(Double valorUnitario) {
		this.valorUnitario = valorUnitario;
	}

}
