package net.floodlightcontroller.mactracker;

import java.util.ArrayList;
import java.util.List;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class MACTrackerResource extends ServerResource {

	@Get("json")
    public List<Long> retrieve() {
        IMACTrackerService imac = (IMACTrackerService)getContext().getAttributes().get(IMACTrackerService.class.getCanonicalName());
        List<Long> l = new ArrayList<Long>();
        l.addAll(imac.getMac());
        return l;
	}
	
}
