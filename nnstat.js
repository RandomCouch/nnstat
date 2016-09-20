var netstat = require('node-netstat');
var ip = require('ip');
var trusted = require('./trusted.json');
const dns = require('dns');

netstat({
	filter: {
		protocol: 'tcp'
	}
}, function(item){
	var protocol = item.protocol;
	var localIP = item.local.address;
	var localPort = item.local.port;
	var remoteIP = item.remote.address;
	var remotePort = item.remote.port;
	var state = item.state;
	var tr = false;
	var hName = "";
	var serviceName = "";
	
	if(!ip.isPrivate(remoteIP) && remoteIP != null && remoteIP != ""){
		//lookup IP
		dns.lookupService(remoteIP, remotePort, (err, hostname, service) => {
			if(!err){
				//Get last 2 of hostname
				//Get service
				dns.resolve(hostname, function(addresses){
					for(var z in addresses){
						//console.log("SERVICE NAME: " + addresses[z]);
					}
				});
				
				hName = hostname;
				var hSplit = hostname.split(".");
				var domain = hSplit[hSplit.length - 2] + "." + hSplit[hSplit.length -1];
				for(var x in trusted.items){
					if(domain == trusted.items[x]){
						tr = true;
					}
				}
				
				if(tr){
					console.log(hName + " is trusted");
				}else{
					console.log(hName + " IS SUSPICIOUS");
					console.log(remoteIP + ":" + remotePort);
					//console.log(state);
				}
				
				
			}else{
				//console.log("Error: " + err);
				console.log(hName + " IS SUSPICIOUS");
				console.log(remoteIP + ":" + remotePort);
			}
		});
	}
	
});