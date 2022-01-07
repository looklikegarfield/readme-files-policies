### threat_gcp_data_configuration_restriction.sentinel
* **GCP_DLP_TRIGGER:** Enforce jobs to have a trigger to ensure they run automatically.
* **GCP_DLP_SAVEFINDINGS:** Enforce that all jobs save their findings into a BQ dataset.

#### Variables 
|Name|Description|
|----|-----|
|selected_node|It is being used locally to have information of node by passing the path.|
|messages|It is being used to hold the complete message of policies violation to show to the user.|

#### Maps
The below map is having entries of the GCP resources in key/value pair, those are required to be validated for Job Trigger policy. Key will be name of the GCP terraform resource ("https://registry.terraform.io/providers/hashicorp/google/latest/docs") and its value will be again combination of key/value pair. Here now key will be ```key``` only and value will be the path of recurrence_period_duration node. Since this is the generic one and can validate recurrence_period_duration associated with any google resource. In order to validate, just need to add corresponding entry of particular GCP terraform resource with the path of its recurrence_period_duration in the below map as given for google_data_loss_prevention_job_trigger or example_rsc.
```
resourceTypesDLPJTMap = {	
	"google_data_loss_prevention_job_trigger": {
		"key":   "triggers.0.schedule.0.recurrence_period_duration",
	},
	   "example_rsc": {
	        "key": "recurrence_period_duration",
        },
}
```
The below map is having entries of the GCP resources in key/value pair, those are required to be validated for Save Finding  policy. It is having two enteries with two keys ```key``` and ```inspect_key```. As per the policy, ```inspect_job.0.actions.0.save_findings.0.output_config.0.table.0.dataset_id``` needs to have appropriate value for the ```dataset_id```. As per terraform, ```inspect_job``` is not required section, so ```inspect_job``` & ```dataset_id``` both need to be validated for null/empty. Key will be name of the GCP terraform resource ("https://registry.terraform.io/providers/hashicorp/google/latest/docs") and its value will be again combination of two key/value pair. Here now first key will be ```key``` only and value will be the path of dataset_id node and for second, key will be ```inspect_key``` and value will be path of inspect_job.

Since this is the generic one and can validate dataset_id associated with any GCP resource. In order to validate, just need to add corresponding entry of particular GCP terraform resource with the path of its dataset_id in the below map as given for google_data_loss_prevention_job_trigger or example_rsc.
```
resourceTypesDLPSFMap = {	
	"google_data_loss_prevention_job_trigger": {
		"key":   "inspect_job.0.actions.0.save_findings.0.output_config.0.table.0.dataset_id",
		"inspect_key" : "inspect_job",
	},
	 "example_rsc": {
	        "key": "example_dataset_id",
		"inspect_key" : "inspect_job",
        },
}
```

#### Methods
The below function is being used to validate the value of parameter "recurrence_period_duration". As per the policy, its value needs to be lied between 1 day to 60 days. It can not be empty/null and will be sufficed with 's'. If the policy won't be validated successfully, it will generate appropriate message to show the users. This function will have below 2-parameters:

* Parameters
  |Name|Description|
  |----|-----|
  |address|The key inside of resource_changes section for particular GCP Resource in tfplan mock|
  |rc|The value of address key inside of resource_changes section for particular GCP Resource in tfplan mock|
      
  ```
  check_job_trigger = func(address, rc) {

	    key = resourceTypesDLPJTMap[rc.type]["key"]

	    selected_node = plan.evaluate_attribute(rc, key)

	    if types.type_of(selected_node) is "null" {
		    return plan.to_string(address) + " does not have " + key +" defined"
	    } else {

		 result = strings.has_suffix(selected_node, "s")

		 min_val = 86400
		 max_val = 86400 * 60

		 if selected_node is not "" and result is true {
			str_value = strings.split(selected_node,"s")[0]

			if float(str_value) >= float(min_val) and float(str_value) <= float(max_val) {
				return null 
			} else {
				return plan.to_string(address) +  " recurrence_period_duration must be set to a time duration greater than or equal to 1 day and can be no  longer than 60 days."							
			}
		 } else {
			return plan.to_string(address) +  " recurrence_period_duration is not having valid input, please provide correctly"				
		}
	  }
  }
  ```

The below function is being used to validate the value of parameter "inspect_job.0.actions.0.save_findings.0.output_config.0.table.0.dataset_id". As per the policy, its value can not be null/empty and must be proper valid dataset_id. If the policy won't be validated successfully, it will generate appropriate message to show the users. This function will have below 2-parameters:

* Parameters
  |Name|Description|
  |----|-----|
  |address|The key inside of resource_changes section for particular GCP Resource in tfplan mock|
  |rc|The value of address key inside of resource_changes section for particular GCP Resource in tfplan mock|

  ```
  check_save_findings = func(address, rc) {

	     key = resourceTypesDLPSFMap[rc.type]["inspect_key"]
	     selected_node = plan.evaluate_attribute(rc, key)
	
	     if selected_node is [] {
		     return plan.to_string(address) + " does not have " + key +" defined"
	     } else {

		  key = resourceTypesDLPSFMap[rc.type]["key"]
		  selected_node = plan.evaluate_attribute(rc, key)
		
		  if selected_node is not ""{
			  return null
		  } else {
			   return plan.to_string(address) +  " dataset id is not having valid input, please provide correctly"			
		  }
	   }
  }
  ```

#### Working Code
The below code will iterate each member of resourceTypesDLPJTMap, which will belong to any resource eg. google_dataproc_cluster etc and each member will have path of its recurrence_period_duration as value. The code will evaluate the recurrence_period_duration's information by using this value and validate the said policy.
```
messages_trigger = {}

for resourceTypesDLPJTMap as key_address, _ {
	# Get all the instances on the basis of type
	allResources = plan.find_resources(key_address)
	for allResources as address, rc {
		message = null
		message = check_job_trigger(address, rc)

		if types.type_of(message) is not "null" {

			gen.create_sub_main_key_list(messages, messages_trigger, address)
			
			append(messages_trigger[address],message)
			append(messages[address],message)
		} 	
	}
}
```

The below code will iterate each member of resourceTypesDLPSFMap, which will belong to any resource eg. google_dataproc_cluster etc and each member will have path of its dataset_id as value. The code will evaluate the dataset_id's information by using this value and validate the said policy.
```
messages_save_findings = {}

for resourceTypesDLPSFMap as key_address, _ {
	# Get all the instances on the basis of type
	allResources = plan.find_resources(key_address)
	for allResources as address, rc {
		message = null
		message = check_save_findings(address, rc)

		if types.type_of(message) is not "null" {

			gen.create_sub_main_key_list(messages, messages_save_findings, address)
			
			append(messages_save_findings[address],message)
			append(messages[address],message)
		} 	
	}
}
```

#### Main Rule
The main function returns true/false as per value of GCP_DLP_TRIGGER and GCP_DLP_SAVEFINDINGS.
```
GCP_DLP_TRIGGER = rule {
 	length(messages_trigger) is 0 
}

GCP_DLP_SAVEFINDINGS = rule {
 	length(messages_save_findings) is 0 
}

main = rule { GCP_DLP_TRIGGER and GCP_DLP_SAVEFINDINGS }
```
