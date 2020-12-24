package net.floodlightcontroller.antiataques;

import java.util.ArrayList;


public class Sospechoso {

	private String ip;
	private String mac;
	private int synNum;
	private int synAckNum;
	private ArrayList<Integer> puertosConsultados=new ArrayList<Integer>();
	private boolean intruso =false;
	
	
	
	public boolean isIntruso() {
		return intruso;
	}
	public void setIntruso(boolean intruso) {
		this.intruso = intruso;
	}
	public String getIp() {
		return ip;
	}
	public void setIp(String ip) {
		this.ip = ip;
	}
	public String getMac() {
		return mac;
	}
	public void setMac(String mac) {
		this.mac = mac;
	}
	public int getSynNum() {
		return synNum;
	}
	public void setSynNum(int synNum) {
		this.synNum = synNum;
	}
	public int getSynAckNum() {
		return synAckNum;
	}
	public void setSynAckNum(int synAckNum) {
		this.synAckNum = synAckNum;
	}
	public ArrayList<Integer> getPuertosConsultados() {
		return puertosConsultados;
	}
	public void setPuertosConsultados(ArrayList<Integer> puertosConsultados) {
		this.puertosConsultados = puertosConsultados;
	}
	
	
}
