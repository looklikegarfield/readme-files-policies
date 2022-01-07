### threat_gcp_kms_enforce.sentinel

#### Imports
```
import "tfplan-functions" as plan
import "strings"
import "types"
```

#### Variables 
|Name|Description|
|----|-----|
|allKmsCryptokeyResources|It is being used locally to have all the KMS Crypto Key resources.|
|allKmsCryptokeySkipInitial|It is being used locally to have all the KMS Crypto Key resources.|

#### Working Code
The below code is used to get all KMS Crypto Key instances google_kms_crypto_key type.
```
allKmsCryptokeyResources = plan.find_resources("google_kms_crypto_key")
allKmsCryptokeySkipInitial = plan.find_resources("google_kms_crypto_key")

```

The below code will iterate each instance of type google_kms_crypto_key and each will have path of its rotation_period as value. The code will evaluate the rotation_period's information by using the value and validate the said policy.
```
cryptokey_messages = {}
for allKmsCryptokeyResources as address, rc {
	key_rotation = plan.evaluate_attribute(rc.change.after, "rotation_period")
	#print(key_rotation)

	is_key_rotation_null = rule { types.type_of(key_rotation) is "null" }
	#print (is_key_rotation_null )

	if is_key_rotation_null is true {

		cryptokey_messages[address] = rc
		print(" rotation Period with null is not allowed ")

	} else {

		if key_rotation == "7776000s" {

			print("Key rotation period is 90 Days")

		} else {

			cryptokey_messages[address] = rc
			print("Please enter key rotation period as 90 Days")

		}
	}

}
```

The below code will iterate each instance of type google_kms_crypto_key and each will have path of its skip_initial_version_creation / import_only as value. The code will evaluate the skip_initial_version_creation's / import_only's information by using the value and validate the said policy.
```
kms_skip_initial_messages = {}
for allKmsCryptokeySkipInitial as address, rc {
	skip_initial = plan.evaluate_attribute(rc.change.after, "skip_initial_version_creation")
	val_import_only = plan.evaluate_attribute(rc.change.after, "import_only")

	is_skip_initial_null = rule { types.type_of(skip_initial) is "null" }

	if is_skip_initial_null is true {

		kms_skip_initial_messages[address] = rc
		print(" skip initial with null value is not allowed ")

	} else {

		if skip_initial is true and val_import_only is true {

			#print ("This is a Match !!!")

		} else {

			kms_skip_initial_messages[address] = rc
			print("kms skip initial version with false value is not allowed")

		}
	}

}
```


#### Main Rule
The main function returns true/false as per value of GCP_KMS_ROTATION & GCP_KMS_IMPORTONLY
```
GCP_KMS_ROTATION = rule { 
    length(cryptokey_messages) is 0 
}

GCP_KMS_IMPORTONLY = rule { 
    length(kms_skip_initial_messages) is 0 
}

main = rule { GCP_KMS_ROTATION and GCP_KMS_IMPORTONLY }
```
