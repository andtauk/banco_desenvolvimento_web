package br.com.api.g2.domain;

import java.util.List;

import br.com.api.g2.enums.CategoriaEnum;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Entity
@Table(name="categoria")
public class Categoria {
	
	@Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column(name="cat_cd_id")
	@Schema(requiredMode = Schema.RequiredMode.REQUIRED, defaultValue= "Identificador unico da categoria")
	private Integer categoriaId;
	
	@Column(name="cat_tx_nome")
	@NotBlank(message="O nome da categoria é obrigatório.")
	@NotNull(message="O nome da categoria é obrigatório.")
	@Size(min=1, max=50, message="O nome da categoria deve ter entre 1 e 50 caracteres.")
	private String nome;
	
	@Column(name="cat_tx_descricao")
	@NotBlank(message="O nome da categoria é obrigatório.")
	@NotNull(message="A descrição da categoria é obrigatória.")
	@Size(min=1, max=200, message="A descrição da categoria deve ter entre 1 e 200 caracteres.")
	private String descricao;
	
	//Uma categoria tem muitos produtos
	@OneToMany(mappedBy="categoria")
	private List<Produto> produtos;
	
	@Enumerated(EnumType.STRING)
    private CategoriaEnum categoriaEnum;

	public Categoria() {

	}

	public Categoria(Integer categoriaId, String nome, String descricao, CategoriaEnum categoriaEnum) {
		this.categoriaId = categoriaId;
		this.nome = nome;
		this.descricao = descricao;
		this.categoriaEnum = categoriaEnum;
	}

	public Integer getCategoriaId() {
		return categoriaId;
	}

	public void setCategoriaId(Integer categoriaId) {
		this.categoriaId = categoriaId;
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

	public CategoriaEnum getCategoriaEnum() {
		return categoriaEnum;
	}

	public void setCategoriaEnum(CategoriaEnum categoriaEnum) {
		this.categoriaEnum = categoriaEnum;
	}

	


	
}
