### gcp_dialogflow_dlp.sentinel
```
GCP_DIALOGFLOW_DLP: As per policy, Enforce use of DLP for Dialogflow agent.
```

#### Imports
```
import "strings"
import "types"
import "tfplan-functions" as plan
```

#### Get all Dialogflow Resources
all_df_Resources = plan.find_resources("google_dialogflow_cx_agent")


#### Working Code
The below code will iterate each member of all_df_Resources and Will check the value of security_settings attribute and validate the said policy. 

```
dlp_messages = {}
for all_df_Resources as address, rc {
	dlp_security = plan.evaluate_attribute(rc.change.after, "security_settings")

	is_dlp_security_null = rule { types.type_of(dlp_security) is "null" }

	if is_dlp_security_null is true {

		dlp_messages[address] = rc
		print(" security_settings with value "null" is not allowed ")

	} else {

		if dlp_security is not null {
            print("The value for google_dialogflow_cx_agent.security_settings is " + dlp_security )

		} else {

			dlp_messages[address] = rc
			print("Please enter correct value for parameter security_settings in google_dialogflow_cx_agent !!!")

		}
	}

}
```

#### Main Rule
The main function returns true/false as per value of GCP_DIALOGFLOW_DLP 
```
GCP_DIALOGFLOW_DLP = rule { length(dlp_messages) is 0 }
main = rule { GCP_DIALOGFLOW_DLP }
```