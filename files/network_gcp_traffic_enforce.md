### network_gcp_traffic_enforce.sentinel
```
GCP_CF_INGRESSSETTINGS: As per policy, Assign a vpc connector where the function should respond to a private VPC resource.
GCP_CF_VPCCONNECTOR:    As per policy, Route all egress traffic to the VPC connector assigned.
```

#### Imports
```
import "strings"
import "types"
import "tfplan-functions" as plan
import "generic-functions" as gen
```

#### Variables
|Name|Description|
|----|-----|
|selected_node|It is being used locally to have information of node by passing the path.|
|messages|It is being used to hold the complete message of policies violation to show to the user.|

#### Maps
The below map is having entries of the GCP resources in key/value pair, those are required to be validated for ingress/vpc connector/egress policy. Key will be name of the GCP terraform resource ("https://registry.terraform.io/providers/hashicorp/google/latest/docs") and its value will be again combination of key/value pair. Here three keys are associated ```key_ingress/key_vpc/key_egress``` and value will be the path of their respective nodes. Since this is the generic one, in order to validate, just need to add corresponding entry of particular GCP terraform resource with the path of required nodes in the below map as given for ```google_cloudfunctions_function```. 
```
resourceTypesTrafficEnforceMap = {	
	"google_cloudfunctions_function": {
		"key_ingress":      "ingress_settings",
        	"key_vpc":   	    "vpc_connector",
		"key_egress":       "vpc_connector_egress_settings",
	},
}
```

#### Methods
The below function is being used to validate the value of parameter "ingress_settings". As per the policy, define ingress traffic settings to only allow requests from private VPC. If the policy won't be validated successfully, it will generate appropriate message to show the users. This function will have below 2-parameters:

* Parameters

  |Name|Description|
  |----|-----|
  |address|The key inside of resource_changes section for particular GCP Resource in tfplan mock|
  |rc|The value of address key inside of resource_changes section for particular GCP Resource in tfplan mock|


  ```
  check_ingress_settings = func(address, rc) {

	key = resourceTypesTrafficEnforceMap[rc.type]["key_ingress"]
	selected_node = plan.evaluate_attribute(rc, key)
	
    if  types.type_of(selected_node) is not "undefined" and selected_node != "ALLOW_INTERNAL_ONLY" {
      return "Requests from private VPC are allowed only for " + plan.to_string(address) + " services, please set value ALLOW_INTERNAL_ONLY"
    } else {
      return null
    }
  }
  ```
The below function is being used to validate the value of parameter "vpc_connector". As per the policy, assign a vpc connector where the function should respond to a private VPC resource. If the policy won't be validated successfully, it will generate appropriate message to show the users. This function will have below 2-parameters:

* Parameters

  |Name|Description|
  |----|-----|
  |address|The key inside of resource_changes section for particular GCP Resource in tfplan mock|
  |rc|The value of address key inside of resource_changes section for particular GCP Resource in tfplan mock|


  ```
  check_vpc_connector = func(address, rc) {

	key = resourceTypesTrafficEnforceMap[rc.type]["key_vpc"]
	selected_node = plan.evaluate_attribute(rc, key)
	
	if types.type_of(selected_node) is "null" or types.type_of(selected_node) is "undefined" {
		
		selected_node = plan.evaluate_attribute(rc.change.after_unknown, key)
		
		if types.type_of(selected_node) is not "null" and  selected_node is true {
			return null
		} else {
			return plan.to_string(address) + " does not have " + key +" defined"
		}		
	} else {
		connector_name = plan.to_string(selected_node)

		if connector_name is "" {
			return plan.to_string(address) + " does not have " + key +" defined"
		} else {		
			contr_arr = strings.split(connector_name, "/")
			contr_arr_p = strings.split(connector_name, "projects") 
			contr_arr_l = strings.split(connector_name, "locations") 
			contr_arr_c = strings.split(connector_name, "connectors")

			if length(contr_arr) > 5 and length(contr_arr_p) > 1 and length(contr_arr_l) > 1 and length(contr_arr_c) > 1 {
				return null
			} else {			
				return "Please provide valid VPC Connector with fully-qualified URI. The format needs to be like projects/*/locations/*/connectors/*"
			}
		}
	 }
  }
  ```
The below function is being used to validate the value of parameter "vpc_connector_egress_settings". As per the policy, route all egress traffic to the VPC connector assigned
. If the policy won't be validated successfully, it will generate appropriate message to show the users. This function will have below 2-parameters:

* Parameters

  |Name|Description|
  |----|-----|
  |address|The key inside of resource_changes section for particular GCP Resource in tfplan mock|
  |rc|The value of address key inside of resource_changes section for particular GCP Resource in tfplan mock|


  ```
  check_vpc_connector_egress = func(address, rc) {

	key_egress = resourceTypesTrafficEnforceMap[rc.type]["key_egress"]
	selected_node = plan.evaluate_attribute(rc, key_egress)

    if types.type_of(selected_node) is "null" or types.type_of(selected_node) is "undefined" {
      return plan.to_string(address) + " does not have " + key_egress +" defined"				
    } else {
      if selected_node is "ALL_TRAFFIC" {
        return null
      } else {
        return plan.to_string(address) + ": " + key_egress +" Route all egress traffic to the VPC connector assigned, please assign its value to ALL_TRAFFIC"
      }
    }
  }
  ```

#### Working Code
The below code will iterate each member of resourceTypesTrafficEnforceMap, which will belong to any resource eg. google_cloudfunctions_function etc and each member will have path of required nodes as value. The code will evaluate their values and validate the said policies. 

```
messages_ingress = {}

for resourceTypesTrafficEnforceMap as key_address, _ {
	
	# Get all the instances on the basis of type
	allResources = plan.find_resources(key_address)
	
	for allResources as address, rc {
		message = null
		message = check_ingress_settings(address, rc)

		if types.type_of(message) is not "null"{
			
			gen.create_sub_main_key_list( messages, messages_ingress, address)

			append(messages_ingress[address],message)
			append(messages[address],message)

		}
	}
}

messages_vpc_connector = {}

for resourceTypesTrafficEnforceMap as key_address, _ {
	
    # Get all the instances on the basis of type	
    allResources = plan.find_resources(key_address)
	
    for allResources as address, rc {
		message = null
		message_sub = check_vpc_connector(address, rc)

		if message_sub is not null {
			message = plan.to_string(message_sub)
		}

		message_sub = check_vpc_connector_egress(address, rc)

		if message_sub is not null {
			if message is not null {
				message = message + plan.to_string(message_sub)
			} else {
				message = plan.to_string(message_sub)
			}
		}

		if types.type_of(message) is not "null" {

			gen.create_sub_main_key_list(messages, messages_vpc_connector, address)
			
			append(messages_vpc_connector[address],message)
			append(messages[address],message)
		} 	
	}
}
```

#### Main Rule
GCP_CF_INGRESSSETTINGS = rule {
	length(messages_ingress) is 0
}

GCP_CF_VPCCONNECTOR = rule {
 	length(messages_vpc_connector) is 0 
}

print(messages)

main = rule { GCP_CF_INGRESSSETTINGS and GCP_CF_VPCCONNECTOR}
```
