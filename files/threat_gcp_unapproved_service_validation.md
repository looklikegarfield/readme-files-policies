### compute_gcp_versioning_enforce.sentinel
```
UNAPPROVED_SERVICES: As per policy, enforce the use of approved services for gcp resource policies.
```

#### Imports
```
import "tfplan/v2" as plan
```

#### Variables 
```

approved_services = [
	"google_dataproc_cluster",
	"google_bigquery_dataset",
	"google_bigquery_table",
	"google_dialogflow_cx_agent",
	"google_container_cluster",
	"google_secret_manager_secret",
	"google_data_loss_prevention_deidentify_template",
	"google_pubsub_topic",
	"google_compute_global_forwarding_rule",
	"google_compute_forwarding_rule",
	"google_compute_network",
	"google_dns_managed_zone",
	"google_compute_firewall",
	"google_kms_key_ring",
	"google_kms_crypto_key",
	"google_kms_key_ring_import_job",
	"google_cloudfunctions_function",
	"google_storage_bucket",
	"google_compute_interconnect_attachment",
	"google_sql_database",
	"google_datastore_index",
	"google_firestore_document",
	"google_spanner_instance",
	"google_spanner_database",
	"google_compute_health_check",
	"google_compute_region_backend_service",
	"google_compute_router",
	"google_compute_subnetwork",
	"google_service_account",
	"google_folder_iam_policy",
	"google_folder_iam_binding",
	"google_folder_iam_member",
	"google_organization_iam_policy",
	"google_organization_iam_binding",
	"google_organization_iam_member",
	"google_project_iam_policy",
	"google_project_iam_binding",
	"google_project_iam_member",
	"google_service_account_iam_policy",
	"google_service_account_iam_binding",
	"google_service_account_iam_member",
	"google_compute_route",
	"google_data_loss_prevention_job_trigger",
	"google_kms_crypto_key_iam_member",
	"google_pubsub_topic_iam_member",
	"google_pubsub_subscription",
	"google_sql_database_instance",
	"google_sql_database",
	"google_sql_user",
	"google_vpc_access_connector",
	"google_cloudfunctions_function_iam_member",
	"google_api_gateway_gateway",
	"google_api_gateway_api_config",
	"google_api_gateway_api",
	"google_storage_bucket_object",
	"google_data_loss_prevention_inspect_template",
	"google_compute_region_instance_group_manager",
	"google_compute_region_backend_service",
	"google_compute_region_url_map",
	"google_compute_region_target_https_proxy",
	"google_compute_firewall",
	"google_compute_region_health_check",
	"google_dns_record_set",
	"google_dns_managed_zone",
]
```

#### Working Code
The below code is used to get all resources type.
```
find_resources = func() {
	resources = filter tfplan.resource_changes as address, rc {
		rc.mode is "managed" and
			(rc.change.actions contains "create" or rc.change.actions contains "update" or
				rc.change.actions contains "read" or
				rc.change.actions contains "no-op")
	}
	return resources
}

all_resources = find_resources()

```

The below code will find each service from approved_services and validate the said policy.
```
messages = {}
for all_resources as address, rc {
	type = rc["type"]
	if type not in approved_services {
		messages[address] = "Resource of type " + type + " is not allowed"
	}
}

print(messages)

```


#### Main Rule
The main function returns true/false as per value of unapproved_services.
```
UNAPPROVED_SERVICES = rule { length(messages) is 0 }

main = rule { UNAPPROVED_SERVICES }
```
