### encryption_gcp_cmek_enforce.sentinel

#### Imports
```
import "tfplan-functions" as plan
import "strings"
import "types"
```

#### Variables 
|Name|Description|
|----|-----|
|selected_node|It is being used locally to have information of node by passing the path.|
|messages| It is being used to hold the complete message of policies violation to show to the user.|

#### Maps
The below map is having entries of the GCP resources in key/value pair, those are required to be validated for CMEK enforce policy. Key will be name of the GCP terraform resource ("https://registry.terraform.io/providers/hashicorp/google/latest/docs") and its value will be again combination of key/value pair. Here now key will be ```key``` only and value will be the path of ```kms_key_name node for google_pubsub_topic / google_secret_manager_secret / google_dataproc_cluster / google_bigquery_dataset ```, ```default_kms_key_name node for google_storage_bucket```, ```encryption_key_name node for google_sql_database_instance```. Since this is the generic one and can validate cmek access associated with any google resource. In order to validate, just need to add corresponding entry of particular GCP terraform resource with the path of its respective node in the below map as given for google_pubsub_topic or google_secret_manager_secret or google_dataproc_cluster or google_bigquery_dataset and ```array``` will have expected value for particular google resource.
```
resourceTypesCMEKKeyMap = {
	"google_pubsub_topic": {
		"key":   "kms_key_name",
		"array": null,
	},
	"google_secret_manager_secret": {
		"key":   "customer_managed_encryption.0.kms_key_name",
		"array": "replication.0.user_managed.0.replicas",
	},
	"google_dataproc_cluster": {
		"key":   "cluster_config.0.encryption_config.0.kms_key_name",
		"array": null,
	},
	"google_bigquery_dataset": {
		"key":   "default_encryption_configuration.0.kms_key_name",
		"array": null,
	},
	"google_storage_bucket": {
		"key":   "encryption.0.default_kms_key_name",
		"array": null,
	},
	"google_sql_database_instance": {
		"key":   "encryption_key_name",
		"array": null,
	},
}
```

#### Methods
The below function is being used to validate the value of parameter ``` kms_key_name / default_kms_key_name / encryption_key_name. ``` As per the policy, its value needs to be as per expected result given respectively in map and it can not be empty/null. If the policy won't be validated successfully, it will generate appropriate message to show the users. This function will have below 2-parameters:

* Parameters

  |Name|Description|
  |----|-----|  
  |address|The key inside of resource_changes section for particular GCP Resource in tfplan mock.|
  |rc|The value of address key inside of resource_changes section for particular GCP Resource in tfplan mock.|
  |kms_key_param|The key inside of resource_changes section for particular GCP Resource in tfplan mock.|
  |array|The key inside of resource_changes section for particular GCP Resource in tfplan mock.|
  ```
 check_for_kms = func(rc, kms_key_param) {
	message = null
	address = rc["address"]
	unknown_kms_key = plan.evaluate_attribute(rc.change.after_unknown, kms_key_param)
	is_unknown_kms_undefined = rule { types.type_of(unknown_kms_key) is "null" }
	if is_unknown_kms_undefined {
		known_kms_key = plan.evaluate_attribute(rc, kms_key_param)
		is_known_kms_undefined = rule { types.type_of(known_kms_key) is "undefined" }
		if is_known_kms_undefined {
			message = plan.to_string(address) + " does not have " + kms_key_param + " defined"
		} else {
			if types.type_of(known_kms_key) is "null" {
				message = plan.to_string(address) + " does not have " + kms_key_param + " defined"
			}
		}
	}
	return message
}

check_multiple_kms = func(address, rc, kms_key_param, array) {
	kms_key_param_array = []
	# messages = {}
	if types.type_of(array) is "null" {
		append(kms_key_param_array, kms_key_param)
	} else {
		kms_attribs = plan.evaluate_attribute(rc, array)
		count = 0
		for kms_attribs as _ {
			append(kms_key_param_array, array + "." + plan.to_string(count) + "." + kms_key_param)
			count += 1
		}
	}
	err = []
	for kms_key_param_array as kkp {
		msg = check_for_kms(rc, kkp)
		if types.type_of(msg) is not "null" {
			append(err, msg)
		}
	}
	return err
}
  ```

#### Working Code
The below code will iterate each member of resourceTypesCMEKKeyMap, which will belong to any resource eg. google_pubsub_topic / google_secret_manager_secret / google_dataproc_cluster / google_bigquery_dataset / google_storage_bucket / google_sql_database_instance etc and each member will have path of its kms_key_name or default_kms_key_name or encryption_key_name as value. The code will evaluate the kms_key_name / default_kms_key_name / encryption_key_name's information by using this value and validate the said policy.

```
allResources = {}
for resourceTypesCMEKKeyMap as rt, _ {
	resources = plan.find_resources(rt)
	for resources as address, rc {
		allResources[address] = rc
	}
}

msgs = {}
for allResources as address, rc {
	msg = check_multiple_kms(
		address,
		rc,
		resourceTypesCMEKKeyMap[rc["type"]]["key"],
		resourceTypesCMEKKeyMap[rc["type"]]["array"],
	)
	if length(msg) > 0 {
		msgs[address] = msg
	}
}
```

#### Main Rule
The main function returns true/false as per value of GCP_RES_CMEK 
```
for msgs as k, v {
	print(k + " =====>" + plan.to_string(v))
}

GCP_RES_CMEK = rule { length(msgs) is 0 }

main = rule { GCP_RES_CMEK }
```
