### network_gcp_port_restriction.sentinel
```
This code Check for restrictedPorts in Firewall Rules and load balancers.
```

#### Imports
```
import "tfplan-functions" as plan
import "strings"
import "types"
```

#### Restricted Ports 
```
restrictedPorts = ["22", "80", "8080", "3389"]
```
#### Get all the instances on the basis of type
```

fwResources = plan.find_resources("google_compute_firewall")
lbResources = plan.find_resources("google_compute_forwarding_rule")
```

#### Working Code

Below code checks for restrictedPorts in Firewall Rules.
```
check_for_restricted_ports = func(restrictedPorts, port) {
	if "-" in port {
		portArr = strings.split(port, "-")
		begin = int(portArr[0])
		end = int(portArr[1])
		for restrictedPorts as eachrPort {
			if int(eachrPort) >= begin and int(eachrPort) <= end {
				return true
			}
		}
	} else {
		if port in restrictedPorts {
			return true
		}
	}
	return false
}

fwRulesMap = {}
for fwResources as address, rc {
	fwRulesMap[address] = []
	allowRules = plan.evaluate_attribute(rc, "allow")
	for allowRules as eachAllow {
		ports = plan.evaluate_attribute(eachAllow, "ports")
		for ports as eachPort {
			append(fwRulesMap[address], eachPort)
		}
	}
}

messages = {}
for fwRulesMap as address, ports {
	for ports as eachPort {
		if check_for_restricted_ports(restrictedPorts, eachPort) {
			message = eachPort + " is not allowed"
			if address in keys(messages) {
				append(messages[address], message)
			} else {
				messages[address] = [message]
			}
		}
	}
}
```
Check for all_ports is enabled in  LoadBalancer.
```

for lbResources as address, rc {
	all_ports = plan.evaluate_attribute(rc, "all_ports")
	if types.type_of(all_ports) is not "null" {
		if all_ports {
			message = "Enabling all_ports is not allowed"
			if address in keys(messages) {
				append(messages[address], message)
			} else {
				messages[address] = [message]
			}
		}
	}

}
```

#### Main Rule
The main function returns true/false as per said policy.
```
PORTS = rule { length(messages) is 0 }

main = rule { PORTS }
```
