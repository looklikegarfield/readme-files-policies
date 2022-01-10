### compute_gcp_dns_log_enforce.sentinel
```
This policy enforces enable logging for DNS Policy
These sentinel policies enforce Wells Fargo security principles
```

#### Imports
```
import "tfplan-functions" as plan
import "strings"
import "types"
```

#### Working Code
The below code is used to get google_dns_policy.
```
fwResources = plan.find_resources("google_dns_policy")
```

The below code will iterate each instance of type google_container_cluster and each will have path of its release_channel as value. The code will evaluate the release_channel's information by using this value and validate the said policy.
```
messages = {}


for fwResources as address,rc {
    enable_logging = plan.evaluate_attribute(rc.change.after, "enable_logging")
        if enable_logging is null or enable_logging is false {
            message =(plan.to_string(enable_logging)+ " is not allowed , it should be true only")
            if address in keys(messages) {
                append(messages[address],message)
            } else {
                messages[address] = [message]}
    }          

}
```


#### Main Rule
The main function returns true/false as per value of GCP_LOG_DNS
```
print(messages)

GCP_LOG_DNS = rule { length(messages) is 0 }


main = rule { GCP_LOG_DNS }
```
