package net.floodlightcontroller.antiataques;

import java.util.ArrayList;

public class Ataque {
	
	private String ipDestino;
	private ArrayList<Integer> puertosConsultados=new ArrayList<Integer>();
	private ArrayList<Integer> puertosQueOfreceServicio=new ArrayList<Integer>();
	private ArrayList<Sospechoso> sospechosos = new ArrayList<Sospechoso>();
	private Long tiempoInicio;
	private Long tiempoUltimo;
	private long mensajesSYN;
	
	
	public String getIpDestino() {
		return ipDestino;
	}
	public void setIpDestino(String ipDestino) {
		this.ipDestino = ipDestino;
	}
	public ArrayList<Integer> getPuertosConsultados() {
		return puertosConsultados;
	}
	public void setPuertosConsultados(ArrayList<Integer> puertosConsultados) {
		this.puertosConsultados = puertosConsultados;
	}
	public ArrayList<Sospechoso> getSospechosos() {
		return sospechosos;
	}
	public void setSospechosos(ArrayList<Sospechoso> sospechosos) {
		this.sospechosos = sospechosos;
	}
	public Long getTiempoInicio() {
		return tiempoInicio;
	}
	public void setTiempoInicio(Long tiempoInicio) {
		this.tiempoInicio = tiempoInicio;
	}
	public Long getTiempoUltimo() {
		return tiempoUltimo;
	}
	public void setTiempoUltimo(Long tiempoUltimo) {
		this.tiempoUltimo = tiempoUltimo;
	}

}
