### network_gcp_ip_restriction.sentinel
```
GCP_INTERNAL_IP: As per policy, Internal IPs will be enabled only, no communication thorugh external ip addresses.
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
|messages| It is being used to hold the complete message of policies violation to show to the user.|

#### Maps
The below map is having entries of the GCP resources in key/value pair, those are required to be validated for ip restriction policy. Key will be name of the GCP terraform resource ("https://registry.terraform.io/providers/hashicorp/google/latest/docs") and its value will be again combination of key/value pair. Here now key will be ```key``` only and value will be the path of ```internal_ip_only node for google_dataproc_cluster```, ```ipv4_enabled node for google_sql_database_instance```, ```load_balancing_scheme node for google_compute_forwarding_rule```, ```visibility node for google_dns_managed_zone```, ```enable_private_nodes node for google_container_cluster``` and ```enable_private_endpoint node for google_container_cluster```. Since this is the generic one and can validate internal ips access associated with any google resource. In order to validate, just need to add corresponding entry of particular GCP terraform resource with the path of its respective node in the below map as given for google_dataproc_cluster or google_sql_database_instance or google_compute_forwarding_rule or google_dns_managed_zone or google_container_cluster and ```expected_result``` will have expected value for particular google resource.
```
resourceTypesInternalIPMap = {
	"google_dataproc_cluster": [{
		"key":             "cluster_config.0.gce_cluster_config.0.internal_ip_only",
		"expected_result":  true,
	}],
	"google_sql_database_instance": [{
		"key":             "settings.0.ip_configuration.0.ipv4_enabled",
		"expected_result":  false,
	}],
	"google_compute_forwarding_rule": [{
		"key":             "load_balancing_scheme",
		"expected_result": "INTERNAL_MANAGED",
	}],
	"google_dns_managed_zone": [{
		"key":             "visibility",
		"expected_result": "private",
	}],
	"google_container_cluster": [{
		"key":             "private_cluster_config.0.enable_private_nodes",
		"expected_result":  true,
	}, 
	{
		"key":             "private_cluster_config.0.enable_private_endpoint",
		"expected_result":  true,
	}],
}
```

#### Methods
The below function is being used to validate the value of parameter ``` internal_ip_only / ipv4_enabled / load_balancing_scheme / visibility / enable_private_nodes / enable_private_endpoint. ``` As per the policy, its value needs to be as per expected result given respectively in map and it can not be empty/null. If the policy won't be validated successfully, it will generate appropriate message to show the users. This function will have below 2-parameters:

* Parameters

  |Name|Description|
  |----|-----|
  |address|The key inside of resource_changes section for particular GCP Resource in tfplan mock.|
  |rc|The value of address key inside of resource_changes section for particular GCP Resource in tfplan mock.|

  ```
  check_internal_ip = func(address, rc) {
	map_results = resourceTypesInternalIPMap[rc.type]
	msg_list = null

	for map_results as rec {
		selected_node = plan.evaluate_attribute(rc, rec.key)
		selected_node_result = rec.expected_result
		
		if types.type_of(selected_node) is "null" or types.type_of(selected_node) is "undefined" {
			if msg_list is null {
				msg_list = []
			}
			append(msg_list, "It does not have " + rec.key + " defined.")
		} else {
			if selected_node is not selected_node_result {				
				if msg_list is null {
					msg_list = []
				}
				append(msg_list,  "The service should be accessible through internal ip only, please set value of " + rec.key + " to " + plan.to_string(selected_node_result) + " to make it as per requirement.")	       
			}
		}
	}
	return  msg_list
  }
  ```

#### Working Code
The below code will iterate each member of resourceTypesInternalIPMap, which will belong to any resource eg. google_dataproc_cluster / google_sql_database_instance / google_compute_forwarding_rule / google_dns_managed_zone / google_container_cluster etc and each member will have path of its internal_ip_only or ipv4_enabled as value. The code will evaluate the internal_ip_only / ipv4_enabled / load_balancing_scheme / visibility / enable_private_nodes / enable_private_endpoint's information by using this value and validate the said policy.

```
messages_ip_internal = {}

for resourceTypesInternalIPMap as key_address, _ {
	# Get all the instances on the basis of type
	allResources = plan.find_resources(key_address)
	for allResources as address, rc {
		message = null
		message = check_internal_ip(address, rc)

		if types.type_of(message) is not "null" {

			gen.create_sub_main_key_list(messages, messages_ip_internal, address)

			append(messages_ip_internal[address], message)
			append(messages[address], message)
		}
	}
}
```

#### Main Rule
The main function returns true/false as per value of GCP_INTERNAL_IP 
```
GCP_INTERNAL_IP = rule {
 	length(messages_ip_internal) is 0 
}

# Main rule
print(messages)

main = rule { GCP_INTERNAL_IP }
```
