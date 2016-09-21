var netstat = require('node-netstat');
var ip = require('ip');
var ps = require('ps-node');
var trusted = require('./trusted.json');
const dns = require('dns');

netstat({
	filter: {
		protocol: 'tcp'
	}
}, function(item){
	var pid = item.pid;
	var protocol = item.protocol;
	var localIP = item.local.address;
	var localPort = item.local.port;
	var remoteIP = item.remote.address;
	var remotePort = item.remote.port;
	var state = item.state;
	var tr = false;
	var hName = "";
	var serviceName = "";
	var processName = "";
	
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
				
				ps.lookup({pid: pid}, function(err, resultList){
					if(err){
						console.log(err);
					}else{
						var process = resultList[0];
						if(process){
							
							var cmd = process.command;
							var cmdSplit = cmd.split("\\");
							var file = cmdSplit[cmdSplit.length - 1];
							if(file == ""){
								file = "Not Found";
							}
							console.log("PROCESS: " + file);
							processName = file;
						}else{
							console.log("Process not found");
						}
					
					}
						if(tr){
							console.log(hName + " is trusted");
						}else{
							console.log(hName + " IS SUSPICIOUS");
							console.log(remoteIP + ":" + remotePort);
							//console.log(state);
						}
					
					
				});
				
				
				
				
				
				
			}else{
				//console.log("Error: " + err);
				//console.log(hName + " IS SUSPICIOUS");
				//console.log(remoteIP + ":" + remotePort);
			}
		});
	}
	
});