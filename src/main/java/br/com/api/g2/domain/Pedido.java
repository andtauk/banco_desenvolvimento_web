package br.com.api.g2.domain;

import java.time.LocalDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonFormat;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;

@Entity
@Table(name="pedido")
public class Pedido {
	
	@Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column(name= "ped_cd_id", nullable=false)
	@Schema(requiredMode = Schema.RequiredMode.REQUIRED, defaultValue= "Identificador unico do pedido")
	private Integer pedidoId;
	
	//adiciona a data e hora
	@Temporal(TemporalType.TIMESTAMP)
    @JsonFormat(pattern = "dd/MM/yyyy HH:mm:ss")
	@Column(name = "ped_dt_data_hora", nullable = false)
	private LocalDateTime data;
	
	//Muitos pedidos tem um usuario
	@ManyToOne
	@JoinColumn(name="fk_usu_cd_id")
	private Usuario usuario;
	
	// Um pedido tem varios item pedido
	// @OneToMany(mappedBy = "pedido")
	// private List<ItemPedido> itensPedido;

	public Pedido() {
		
	}

	public Pedido(Integer pedidoId, LocalDateTime data, Usuario usuario) {
		this.usuario = usuario;
		this.pedidoId = pedidoId;
		this.data = data;
	}

	public Integer getPedidoId() {
		return pedidoId;
	}

	public void setPedidoId(Integer pedidoId) {
		this.pedidoId = pedidoId;
	}

	public LocalDateTime getData() {
		return data;
	}

	public void setData(LocalDateTime data) {
		this.data = data;
	}

	public Usuario getUsuario() {
		return usuario;
	}

	public void setUsuario(Usuario usuario) {
		this.usuario = usuario;
	}
}
