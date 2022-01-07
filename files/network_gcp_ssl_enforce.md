### network_gcp_ssl_enforce.sentinel
```
GCP_SSL_ENFORCE: As per policy, only https access will be allowed.
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
The below map is having entries of the GCP resources in key/value pair, those are required to be validated for SSL enforcement policy. Key will be name of the GCP terraform resource ("https://registry.terraform.io/providers/hashicorp/google/latest/docs") and its value will be again combination of key/value pair. Here now key will be ```key``` only and value will be the path of enable_http_port_access node. Since this is the generic one and can validate enable_http_port_access associated with any GCP resource. In order to validate, just need to add corresponding entry of particular GCP terraform resource with the path of its enable_http_port_access in the below map as given for google_dataproc_cluster or example_rsc.
```
resourceTypesSSLEnforceMap = {	
	"google_dataproc_cluster": {
		"key":   	"cluster_config.0.endpoint_config.0.enable_http_port_access",
	},
	"example_rsc": {
	     "key": "someroot.enable_http_port_access",
	},
}
```

#### Methods
The below function is being used to validate the value of parameter ```enable_http_port_access```. As per the policy, its value can not be true. If the policy will not be validated successfully, it will generate appropriate message to show the users. This function will have below 2-parameters:

* Parameters

  |Name|Description|
  |----|-----|
  |address|The key inside of resource_changes section for particular GCP Resource in tfplan mock.|
  |rc|The value of address key inside of resource_changes section for particular GCP Resource in tfplan mock.|

  ```
  check_endpoint_config = func(address, rc) {

	key = resourceTypesSSLEnforceMap[rc.type]["key"]
	selected_node = plan.evaluate_attribute(rc, key)
	
	if  selected_node {
		return "Http port's access needs to be disabled for the " + plan.to_string(address) + " services, please set value false to make it disabled"
	} else {
		return null
	}
  }
  ```

#### Working Code
The below code will iterate each member of resourceTypesSSLEnforceMap, which will belong to any resource eg. google_dataproc_cluster etc and each member will have path of its enable_http_port_access as value. The code will evaluate the enable_http_port_access's information by using this value and validate the said policy.
```
messages_http = {}

for resourceTypesSSLEnforceMap as key_address, _ {
	
	# Get all the instances on the basis of type
	allResources = plan.find_resources(key_address)
	
	for allResources as address, rc {
		message = null
		message = check_endpoint_config(address, rc)

		if types.type_of(message) is not "null"{
			
			gen.create_sub_main_key_list( messages, messages_http, address)

			append(messages_http[address],message)
			append(messages[address],message)

		}
	}
}
```

#### Main Rule
The main function returns true/false as per value of GCP_SSL_ENFORCE 
```
GCP_SSL_ENFORCE = rule {
	length(messages_http) is 0
}

main = rule { GCP_SSL_ENFORCE }
