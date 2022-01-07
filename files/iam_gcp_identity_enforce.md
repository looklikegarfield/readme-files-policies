### iam_gcp_identity_enforce.sentinel
```
GCP_GKE_WORLOADIDENT: As per policy, enforce enabling Workload Identity.
```

#### Imports
```
import "tfplan/v2" as tfplan
import "tfplan-functions" as plan
import "strings"
import "types"
```

#### Variables 
|Name|Description|
|----|-----|
|allGkeInstances|It is being used locally to have all the GKE resources.|

#### Working Code
The below code is used to get all GKE instances google_container_cluster type.
```
allGkeInstances = plan.find_resources("google_container_cluster")
```

The below code will iterate each instance of type google_container_cluster and each will have path of its release_channel as value. The code will evaluate the workload_identity_config's information by using this value and validate the said policy.
```
datasource = tfplan.raw.prior_state.values.root_module.resources
is_null_datasource = rule { types.type_of(datasource) == "undefined" }

workload_pool_var = ""
if not is_null_datasource {
	projects = filter tfplan.raw.prior_state.values.root_module.resources as _, rc {
		rc.type is "google_project"
	}

	project_id = ""
	for projects as address, rc {
		project_id = plan.evaluate_attribute(rc, "values.project_id")
		#print(project_id)
	}

	workload_pool_var = plan.to_string(project_id) + ".svc.id.goog"
}
print("workload_pool_var==>" + plan.to_string(workload_pool_var))

violations_workload_pool = {}
for allGkeInstances as address, rc {

	workload_pool = plan.evaluate_attribute(rc.change.after, "workload_identity_config")
	print(workload_pool)

	isnull_workload_pool = rule { types.type_of(workload_pool) == "null" }
	#print(isnull_workload_pool)
	if isnull_workload_pool {
		print("The value for  " + address + " Can't be Null ")
		violations_workload_pool[address] = rc

	} else {
		if workload_pool_var == "" {
			violations_workload_pool[address] = rc
			print("For resource: " + address + " Please define data source for resource type: google_project")
		} else {
			if not (workload_pool[0]["workload_pool"] == workload_pool_var) {
				print("For the resource: " + plan.to_string(address) + " The value for workload_identity_config.workload_pool can only be ${data.google_project.project.project_id}.svc.id.goog")
				violations_workload_pool[address] = rc
			}
		}
	}
}
```

#### Main Rule
The main function returns true/false as per value of GCP_GKE_WORLOADIDENT
```
GCP_GKE_WORLOADIDENT = rule { length(violations_workload_pool) is 0 }

main = rule { GCP_GKE_WORLOADIDENT }
```
