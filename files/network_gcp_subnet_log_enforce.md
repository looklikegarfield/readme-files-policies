### network_gcp_subnet_log_enforce.sentinel
```
All GCE resources following all the policies related to subnet's logging.
```

#### Imports
```
import "strings"
import "types"
import "tfplan-functions" as plan
import "generic-functions" as gen
```

#### Variables 
```

selected_node = null
messages = {}
```
#### Get all the instances on the basis of type
```
allResources = plan.find_resources("google_compute_subnetwork")
```
### Methods

#### Following function is being used to validate the value of flow_sampling
```
check_flow_sampling = func(address, rc) {

	key = "log_config.0.flow_sampling"
	selected_node = plan.evaluate_attribute(rc, key)

	if selected_node is not 1 {
		return plan.to_string(address) + " the value of the field flow_sampling must be 1, please correct it."
	} else {
		return null
	}
}
```
#### Following function is being used to validate the value of metadata
```
check_metadata = func(address, rc) {

	key = "log_config.0.metadata"
	selected_node = plan.evaluate_attribute(rc, key)

	if selected_node is "INCLUDE_ALL_METADATA" {
		return null
	} else {
		return plan.to_string(address) + "  the value of the field metadata must be 'INCLUDE_ALL_METADATA', please correct it."
	}
}
```
#### Working Code

Below code will validating Subnet's logging flow_sampling
```
messages_flow_sampling = {}

for allResources as address, rc {
	message = null
	message = check_flow_sampling(address, rc)

	if types.type_of(message) is not "null" {

		gen.create_sub_main_key_list(messages, messages_flow_sampling, address)

		append(messages_flow_sampling[address], message)
		append(messages[address], message)
	}
}
```
Below code will validating Subnet's logging metadata.
```
messages_metadata = {}

for allResources as address, rc {
	message = null
	message = check_metadata(address, rc)

	if types.type_of(message) is not "null" {

		gen.create_sub_main_key_list(messages, messages_metadata, address)

		append(messages_metadata[address], message)
		append(messages[address], message)
	}
}

```


#### Main Rule
The main function returns true/false as per value of unapproved_services.
```
GCP_VPC_LOGS1 = rule {
	length(messages_flow_sampling) is 0
}

GCP_VPC_LOGS2 = rule {
	length(messages_metadata) is 0
}

GCP_VPC_LOGS = rule { GCP_VPC_LOGS1 and GCP_VPC_LOGS2 }

# Main rule
print(messages)

main = rule { GCP_VPC_LOGS }
```
