package net.floodlightcontroller.mactracker;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.restserver.IRestApiService;

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

public class MACTracker implements IOFMessageListener, IFloodlightModule, IMACTrackerService {

protected IFloodlightProviderService floodlightProvider;
protected Set<Long> macAddresses;
protected static Logger logger;
protected IRestApiService restApi;

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return MACTracker.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return (type.equals(OFType.PACKET_IN) && name.equals("forwarding"));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IMACTrackerService.class);
	    return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		m.put(IMACTrackerService.class, this);
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =
		        new ArrayList<Class<? extends IFloodlightService>>();
		    l.add(IFloodlightProviderService.class);
		    l.add(IRestApiService.class);
	    return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
	    floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	    macAddresses = new ConcurrentSkipListSet<Long>();
	    logger = LoggerFactory.getLogger(MACTracker.class);
	    restApi = context.getServiceImpl(IRestApiService.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		restApi.addRestletRoutable(new MACTrackerWebRoutable());

	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		 Ethernet eth =
	                IFloodlightProviderService.bcStore.get(cntx,
	                                            IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		 
	        Long sourceMACHash = eth.getSourceMACAddress().getLong(); //obitene la MAC
	        if (!macAddresses.contains(sourceMACHash)) {
	            macAddresses.add(sourceMACHash); //Se añade a la lista
	            logger.info("MAC Address: {} seen on switch: {}",
	                    eth.getSourceMACAddress().toString(),
	                    sw.getId().toString());
	        }
	        return Command.CONTINUE; 
	}

	@Override
	public Set<Long> getMac() {
		// TODO Auto-generated method stub
		return macAddresses;
	}

}
