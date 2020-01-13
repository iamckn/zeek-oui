##! This script adds link-layer address (MAC) information to the connection logs

@load base/protocols/conn

module Conn;

export {
    ## Idx is used as an identifier to load an input file into 
    ## a table.
    type Idx: record {
        ## OUI is the unique identifier for an organization that
        ## manufactures hardware.
        oui:    string;
    };

    ## Val is the record that is read in from the input file
    type Val: record {
        ## vendor is the name of the vendor that created the device 
        ## marked with an OUI.
        vendor: string;
    };

    ## vendors is a table of OUI references paired with manufacturer
    ## names to be used to identify network devices.
    global mac_vendors: table[string] of Val = table()
        &default=Val($vendor="unknown");

    ## lookup_oui is used to lookup a mac address and return the 
    ## name of an organization that has manufactured the device.
    global lookup_oui: function(mac_addr: string): string;
}

# lookup_oui is used to lookup a mac address and return the name
# of an organization that has manufactured the device.
# Args:
# mac_addr: string
#   the mac address to lookup the OUI for
# Returns:
# string:
#   the manufacturer/organization that the OUI for the device
#   identifies.
function lookup_oui(mac_addr: string): string 
    {
    local prefix = mac_addr[:8];
    return mac_vendors[prefix]$vendor;
    }

event zeek_init()
    {
    # create an input file to be used to learn OUI data. This input
    # reads the data into the vendors table and will reread the 
    # table if the file is rewritten.
    Input::add_table([$source=fmt("%s/oui.dat", @DIR), 
        $name="mac_vendors", 
        $idx=Idx, 
        $val=Val, 
        $destination=mac_vendors,
        $mode=Input::REREAD]);
    }

redef record Info += {
	## Link-layer address of the originator, if available.
	#orig_l2_addr: string	&log &optional;
	## Link-layer address of the responder, if available.
	#resp_l2_addr: string	&log &optional;
	#Vendor of the originator, if available
	orig_mac_oui: string &log &optional;
};

# Add the vendor to the Conn::Info structure after the connection
# has been removed. This ensures it's only done once, and is done before the
# connection information is written to the log.
event connection_state_remove(c: connection)
	{
	if ( c$orig?$l2_addr )
		c$conn$orig_mac_oui = lookup_oui(c$orig$l2_addr);
	}
