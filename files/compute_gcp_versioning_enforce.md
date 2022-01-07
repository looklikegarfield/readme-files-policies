### compute_gcp_versioning_enforce.sentinel
```
GCP_GKE_RELEASECHANNEL: As per policy, enforce subscription to the STABLE  release channel when the label environment has the value prod.
GCP_GKE_DATAPLANEV2: As per policy, enforce the use of Dataplane-V2 for GKE network policies.
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
|allGkeInstances|It is being used locally to have all the GKE resources.|
|violations_release_channel| It is being used to hold the complete message of policies violation for release channel to show to the user.|

#### Working Code
The below code is used to get all GKE instances google_container_cluster type.
```
allGkeInstances = plan.find_resources("google_container_cluster")
```

The below code will iterate each instance of type google_container_cluster and each will have path of its release_channel as value. The code will evaluate the release_channel's information by using this value and validate the said policy.
```
violations_release_channel = {}
for allGkeInstances as address, rc {

	#release_channel = plan.evaluate_attribute(rc.change.after.release_channel[0],"channel")
	release_channel = plan.evaluate_attribute(rc.change.after, "release_channel")
	# print(release_channel[0]["channel"])
	print(release_channel)

	isnull_release_channel = rule { types.type_of(release_channel) == "null" }
	print(isnull_release_channel)
	if isnull_release_channel {
		#print("release_channel can't be null")
		print("The value for  " + address + " Can't be Null ")
		violations_release_channel[address] = rc

	} else {

		if not (release_channel[0]["channel"] == "STABLE") {
			#print("Only STABLE option is permissible for Release Channel")
			print("The value for  " + address + " can only be STABLE")
			violations_release_channel[address] = rc

		}
	}
}
```

The below code will iterate each instance of type google_container_cluster and each will have path of its datapath_provider as value. The code will evaluate the datapath_provider's information by using this value and validate the said policy.
```
violations_dataplane = {}
for allGkeInstances as address, rc {

	dataplane = plan.evaluate_attribute(rc.change.after, "datapath_provider")
	isnull_dataplane = rule { types.type_of(dataplane) == "null" }
	print("Dataplane: " + plan.to_string(isnull_dataplane))

	if isnull_dataplane {
		violations_dataplane[address] = rc
		#print("Dataplane value can't be Null")
		print("The value for  " + address + " Can't be Null ")

	} else {

		if not (dataplane == "ADVANCED_DATAPATH") {
			print("For Dataplane, only ADVANCED_DATAPATH value is supported")
			violations_dataplane[address] = rc
		}
	}

}
```


#### Main Rule
The main function returns true/false as per value of GCP_GKE_RELEASECHANNEL & GCP_GKE_DATAPLANEV2
```
GCP_GKE_RELEASECHANNEL = rule { 
    length(violations_release_channel) is 0 
}

GCP_GKE_DATAPLANEV2 = rule { 
    length(violations_dataplane) is 0 
}

main = rule { GCP_GKE_RELEASECHANNEL and GCP_GKE_DATAPLANEV2 }
```
