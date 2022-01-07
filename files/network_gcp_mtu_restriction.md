### network_gcp_mtu_restriction.sentinel
```
GCP_IC_MTU: As per policy, the mtu value should be 1500 and could not be a null value.
```

#### Imports
```
import "strings"
import "types"
import "tfplan-functions" as plan
```
#### Maps
The below map is having entries of the GCP resources in key/value pair, those are required to be validated for mtu restriction policy. Key will be name of the GCP terraform resource ("https://registry.terraform.io/providers/hashicorp/google/latest/docs") and its value will be again combination of key/value pair. Here now key will be ```key``` only and value will be the path of ```mtu``` node. Since this is the generic one and can validate ```mtu``` associated with any google resource. In order to validate, just need to add corresponding entry of particular GCP terraform resource with the path of its ```mtu``` in the below map as given for google_compute_interconnect_attachment or example_rsc.
```
resourceTypesInterConnectAttachmentMap = {	
	"google_compute_interconnect_attachment": {
		"key":   "mtu",
	},
	"google_compute_network": {
		"key":   "mtu",
	},
	"example_rsc": {
	     "key": "someroot.mtu",
	},
}
```

#### Working Code
The below code will iterate each member of resourceTypesInterConnectAttachmentMap, which will belong to any resource eg. google_compute_interconnect_attachment/google_compute_network/example_rsc etc and each member will have path of its ```mtu``` as value. The code will evaluate the mtu's information by using this value and validate the said policy. This is being used to validate the value of parameter ```mtu```. As per the policy, its value needs to be 1500 and it can not be empty/null. If the policy won't be validated successfully, it will generate appropriate message to show the users.
```
mtu_messages = {}
for resourceTypesInterConnectAttachmentMap as key_address, _ {
	# Get all the instances on the basis of type
	allResources = plan.find_resources(key_address)

    for allResources as address, rc {
        key = resourceTypesInterConnectAttachmentMap[rc.type]["key"]

        uk_mtu = plan.evaluate_attribute(rc.change.after_unknown, key)
        
        if types.type_of(uk_mtu) is "null" {
            k_mtu = plan.evaluate_attribute(rc, key)
            
            if int(k_mtu) is not 1500 {
                mtu_messages[address] = "Resource " + address + " has mtu with value " + plan.to_string(k_mtu) + " which is not allowed"
            }
        } else {
            mtu_messages[address] = "Resource " + address + " has default mtu which is not allowed"
        }
    }
}
```

#### Main Rule
The main function returns true/false as per value of GCP_IC_MTU 
```
GCP_IC_MTU = rule { length(mtu_messages) is 0 }

main = rule { GCP_IC_MTU }
```
