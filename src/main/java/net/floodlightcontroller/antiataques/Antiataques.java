package net.floodlightcontroller.antiataques;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.internal.Device;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

public class Antiataques implements IOFMessageListener, IFloodlightModule {

	ArrayList<Ataque> ataques;
	ArrayList<String> MACIntrusas;
	protected static Logger logger;
	protected IFloodlightProviderService floodlightProvider;
	boolean ipSpoofingEn;
	boolean portScanningEn;
	long umbralTiempo;
	int umbralPuertosXAtaque;
	int umbralPuertosXSospechoso;
	int maxDifSconAS;
	
	
	@Override
	public String getName() {
		return Antiataques.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {

		return (type== OFType.PACKET_IN && name.equalsIgnoreCase("forwarding"));
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {

		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {

		Collection<Class<? extends IFloodlightService>> l =
		        new ArrayList<Class<? extends IFloodlightService>>();
		    l.add(IFloodlightProviderService.class);
		    return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		logger = LoggerFactory.getLogger(Antiataques.class);
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		ataques = new ArrayList<>();
		ipSpoofingEn=true;
		portScanningEn=true;
		umbralPuertosXAtaque=6;
		umbralPuertosXSospechoso=2;
		umbralTiempo=1000;
		maxDifSconAS = 10;

	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		if (ipSpoofingEn)
		{
			ipSpoofingDetection(msg,cntx, sw);
		}
		if (portScanningEn)
		{
			portScanningDetection(msg,cntx);
		}
		if (isIntruder(msg, cntx)) return Command.STOP;
		else return Command.CONTINUE;
	}
	
	public void portScanningDetection(OFMessage msg, FloodlightContext cntx)
	{	
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		 if(eth.getEtherType().equals(EthType.IPv4)) {
	        IPv4 ip = (IPv4) eth.getPayload();
	        if (ip.getProtocol().equals(IpProtocol.TCP)) {
	        	TCP tcp = (TCP) ip.getPayload();
	        	int pos = ubicarHost(ip);
	        	if(tcp.getFlags() == 0x02 ){ //Si es SYN
	        		if(pos==-1) //Quiere decir que es un nuevo host
	        		{
	        			Ataque ataque = new Ataque();
	        			ataque.setIpDestino(ip.getDestinationAddress().toString());
	        			ataque.setTiempoInicio(System.currentTimeMillis());
	        			pos=ataques.size();
	        			ataques.add(ataque);
	        		}
	        		Ataque ataque = ataques.get(pos);
	        		
	        		int posSos = ubicarSospechoso(ip, eth, pos);
	        		if(posSos==-1) //Quiere decir que es un nuevo sospechoso
	        		{
	        			Sospechoso sospechoso = new Sospechoso();
	        			sospechoso.setIp(ip.getSourceAddress().toString());
	        			sospechoso.setMac(eth.getSourceMACAddress().toString());
	        			posSos=ataque.getSospechosos().size();
	        			ataque.getSospechosos().add(sospechoso);
	        		}
	        		Sospechoso sospechoso = ataque.getSospechosos().get(posSos);
	        		if(!sospechoso.getPuertosConsultados().contains(tcp.getDestinationPort().getPort()))
	        			sospechoso.getPuertosConsultados().add(tcp.getDestinationPort().getPort());
	        		sospechoso.setSynNum(sospechoso.getSynNum()+1);
	        		
	        		if(!ataque.getPuertosConsultados().contains(tcp.getDestinationPort().getPort()))
	        			ataque.getPuertosConsultados().add(tcp.getDestinationPort().getPort());
	        		ataque.getSospechosos().set(posSos, sospechoso);
	        		ataque.setTiempoUltimo(System.currentTimeMillis());
	        		ataques.set(pos, ataque);
	        		
	        		if((ataque.getTiempoUltimo()-ataque.getTiempoInicio())>=umbralTiempo) //Se acabo el tiempo de evaluación
	        		{
	        			if(ataque.getPuertosConsultados().size()>=umbralPuertosXAtaque) //Se evalua si se han consultado más puertos de lo permitido
	        			{
	        				for (Sospechoso s : ataque.getSospechosos()) //Se evaluan los sospechosos
	        				{
	        					//Si un sospechoso evalua mas puertos de lo permitido o tiene una gran numero de SYN respecto a SY-NACK
	        					//Se considera intruso
	        					if(s.getPuertosConsultados().size()>=umbralPuertosXSospechoso) 
	        						{
	        							s.setIntruso(true);
	        							MACIntrusas.add(s.getMac());
	        						}
	        					if((s.getSynNum()-s.getSynAckNum())>=maxDifSconAS) 
	        						{
	        							s.setIntruso(true);
	        							MACIntrusas.add(s.getMac());
	        						}
	        				}
	        			}
	        		}
	        	}
	        	
	        	
	        	if(tcp.getFlags() == 0x12 ){ //Si es SYN-ACK
	        		if(pos!=-1) //Solo una validación
	        		{
	        			int posSos = ubicarSospechoso(ip, eth, pos);
	        			if(posSos!=-1)
	        			{
	        				Sospechoso sospechoso = ataques.get(pos).getSospechosos().get(posSos);
	        				ataques.get(pos).getSospechosos().get(posSos).setSynAckNum(sospechoso.getSynAckNum()+1);
	        			}
	        		}
	        	}	
	        }
		 }
		
	}
	
	public void ipSpoofingDetection(OFMessage msg, FloodlightContext cntx, IOFSwitch sw)
	{
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		 if(eth.getEtherType().equals(EthType.IPv4)) {
	        IPv4 ip = (IPv4) eth.getPayload();
	        String ipSol = ip.getDestinationAddress().toString();
	        String MACSol = eth.getDestinationMACAddress().toString();
	        //TODO obtener el attachment point
	        
	        /*TODO a partir de la ip obtener la MAC registrada segun el controlador y el attachment point respectivo
	         * Si son diferentes, se identifica al acto que el dueño de la MAC es un intruso atacando al respectivo host
	         */
	        DeviceManagerImpl deviceManagerImpl = new DeviceManagerImpl();
	        Collection<? extends IDevice> equiposCollection =deviceManagerImpl.getAllDevices();
	        ArrayList<IDevice> equipos = new ArrayList<>(equiposCollection);
	        
	        boolean encontroIp = false;
	        boolean ipCoincideConMac=false;
	        for (IDevice id : equipos)
	        {
	        	if(id.getIPv4Addresses().toString().equalsIgnoreCase(ipSol))
	        	{
	        		encontroIp = true;
	        		if(id.getMACAddressString().equalsIgnoreCase(MACSol)) ipCoincideConMac=true;
	        		else ipCoincideConMac=false;
	        		if(ipCoincideConMac); //Evaluar atachment point vecinos 
	        	}
	        }
	        
	        if(!ipCoincideConMac)
	        {
	        	MACIntrusas.add(MACSol);
	        }
	        }
	}
	
	public int ubicarHost(IPv4 ip)
	{
		int rpta = -1;
		
		int pos=0;
		for(Ataque a : ataques)
		{
			if (a.getIpDestino().equals(ip.getDestinationAddress().toString())) rpta=pos;
			pos++;
		}
	
		return rpta;
	}
	
	public int ubicarSospechoso(IPv4 ip, Ethernet eth, int pos)
	{
		int rpta = -1;
		
		int cont=0;
		for(Sospechoso s : ataques.get(pos).getSospechosos())
		{
			if (s.getIp().equals(ip.getSourceAddress().toString()) || s.getMac().equals(eth.getSourceMACAddress().toString())) 
				rpta=cont;
			cont++;
		}
		return rpta;
	}
	
	public boolean isIntruder(OFMessage msg, FloodlightContext cntx)
	{
		boolean intruso = false;
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        for (Ataque a : ataques)
        {
        	for(Sospechoso s : a.getSospechosos())
        	{
        		if (s.isIntruso() && (s.getMac().equals(eth.getDestinationMACAddress().toString()))) intruso =true;
        	}
        }
        
        String mac = eth.getDestinationMACAddress().toString();
        if (MACIntrusas.contains(mac)) intruso = true;
        
		return intruso;
	}

}
