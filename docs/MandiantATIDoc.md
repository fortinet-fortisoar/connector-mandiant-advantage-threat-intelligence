## About the connector

Mandiant Advantage Threat Intelligence provides automated access to indicators of compromise (IOCs) IP addresses, domain names, URLs threat actors are using, via the indicators, allows access to full length finished intelligence in the reports, allows for notificaiton of threats to brand and keyword monitoring via the alerts, and finally allows searching for intelligence on the adversary with the search. This connector facilitates automated operations such as indicators, actors, malware, reports, campaigns, and vulnerabilities.
<p>This document provides information about the Mandiant Advantage Threat Intelligence Connector, which facilitates automated interactions, with a Mandiant Advantage Threat Intelligence server using FortiSOAR&trade; playbooks. Add the Mandiant Advantage Threat Intelligence Connector as a step in FortiSOAR&trade; playbooks and perform automated operations with Mandiant Advantage Threat Intelligence.</p>

### Version information

Connector Version: 1.0.0


Authored By: Fortinet

Certified: No

## Installing the connector

<p>Use the <strong>Content Hub</strong> to install the connector. For the detailed procedure to install a connector, click <a href="https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector" target="_top">here</a>.</p><p>You can also use the <code>yum</code> command as a root user to install the connector:</p>
<pre>yum install cyops-connector-mandiant-advantage-threat-intelligence</pre>

## Prerequisites to configuring the connector

- You must have the credentials of Mandiant Advantage Threat Intelligence server to which you will connect and perform automated operations.
- The FortiSOAR&trade; server should have outbound connectivity to port 443 on the Mandiant Advantage Threat Intelligence server.

## Minimum Permissions Required

- Not applicable

## Configuring the connector

For the procedure to configure a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/configuring-a-connector/1/configuring-a-connector)

### Configuration parameters

<p>In FortiSOAR&trade;, on the Connectors page, click the <strong>Mandiant Advantage Threat Intelligence</strong> connector row (if you are in the <strong>Grid</strong> view on the Connectors page) and in the <strong>Configurations</strong> tab enter the required configuration details:</p>
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Server URL</td><td>The service-based URI to which you will connect and perform the automated operations.
</td>
</tr><tr><td>Public Key</td><td>The unique Mandiant Advantage Threat Intelligence Public Key used to create an authentication token required to access the Mandiant Advantage Threat Intelligence API.
</td>
</tr><tr><td>Private Key</td><td>The unique Mandiant Advantage Threat Intelligence Private Key used to create an authentication token required to access the Mandiant Advantage Threat Intelligence API.
</td>
</tr><tr><td>Verify SSL</td><td>Specifies whether the SSL certificate for the server is to be verified or not. <br/>By default, this option is set to True.</td></tr>
</tbody></table>

## Actions supported by the connector

The following automated operations can be included in playbooks and you can also use the annotations to access operations from FortiSOAR&trade; release 4.10.0 and onwards:
<table border=1><thead><tr><th>Function</th><th>Description</th><th>Annotation and Category</th></tr></thead><tbody><tr><td>Get Indicators List</td><td>Retrieves all indicators from Mandiant Advantage Threat Intelligence based on the input parameters you have specified.</td><td>get_indicators <br/>Investigation</td></tr>
<tr><td>Get Indicator Details</td><td>Retrieves a specific indicator details from Mandiant Advantage Threat Intelligence based on the indicator value you have specified.</td><td>get_indicator_details <br/>Investigation</td></tr>
<tr><td>Get Threat Actors List</td><td>Retrieves all actors from Mandiant Advantage Threat Intelligence based on the input parameters you have specified.</td><td>get_actors <br/>Investigation</td></tr>
<tr><td>Get Threat Actor Details</td><td>Retrieves a specific actor details from Mandiant Advantage Threat Intelligence based on the actor ID or name you have specified.</td><td>get_actor_details <br/>Investigation</td></tr>
<tr><td>Get Malware Families List</td><td>Retrieves all malware from Mandiant Advantage Threat Intelligence based on the input parameters you have specified.</td><td>get_malware <br/>Investigation</td></tr>
<tr><td>Get Malware Family Details</td><td>Retrieves a specific malware details from Mandiant Advantage Threat Intelligence based on the malware ID or name you have specified.</td><td>get_malware_details <br/>Investigation</td></tr>
<tr><td>Get Campaigns List</td><td>Retrieves all campaigns from Mandiant Advantage Threat Intelligence based on the input parameters you have specified.</td><td>get_campaign <br/>Investigation</td></tr>
<tr><td>Get Campaign Details</td><td>Retrieves a specific campaign details from Mandiant Advantage Threat Intelligence based on the campaign ID you have specified.</td><td>get_campaign_details <br/>Investigation</td></tr>
<tr><td>Get Vulnerabilities List</td><td>Retrieves all vulnerabilities from Mandiant Advantage Threat Intelligence based on the input parameters you have specified.</td><td>get_vulnerability <br/>Investigation</td></tr>
<tr><td>Get Reports List</td><td>Retrieves all reports from Mandiant Advantage Threat Intelligence based on the input parameters you have specified.</td><td>get_reports <br/>Investigation</td></tr>
<tr><td>Get Report Details</td><td>Retrieves a specific report details from Mandiant Advantage Threat Intelligence based on the report ID you have specified.</td><td>get_report_details <br/>Investigation</td></tr>
</tbody></table>

### operation: Get Indicators List

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Start DateTime</td><td>Select the DateTime using which you want to filter the result set to only include only those items that have been created after the specified timestamp.
</td></tr><tr><td>End DateTime</td><td>Select the DateTime using which you want to filter the result set to only include only those items that have been created before the specified timestamp.
</td></tr><tr><td>Limit</td><td>Specify the maximum number of results, per page, that this operation should return. By default, this option is set as 25 and maximum allowed 1000.
</td></tr><tr><td>Confidence Score</td><td>Specify the minimum indicator confidence score that this operation to return.
</td></tr><tr><td>Exclude Open Source Indicator</td><td>Select this checkbox if open source indicators should be returned.
</td></tr><tr><td>Include Reports</td><td>Select this checkbox if you want this operation to include related reports.
</td></tr><tr><td>Report Limit</td><td>Specify the maximum number of reports to include in response, that this operation should return. By default, this option is set as 25 and maximum allowed 1000.
</td></tr><tr><td>Include Campaigns</td><td>Select this checkbox if you want this operation to include related campaigns.
</td></tr><tr><td>Skip Token</td><td>Skiptoken is only used if a previous operation returned a partial result. If a previous response contains a next element, the value of the next element will include a skiptoken parameter that specifies a starting point to use for subsequent calls. When using next no other parameters should be included in the request. Note: The token returned is valid for 10 minutes.
</td></tr><tr><td>Sort By</td><td>Specify the name of the field based on which you want to sort the result (indicators) retrieved by this operation. It can also be extended to support sort order by appending a ':' and sort order.
</td></tr><tr><td>Sort Order</td><td>Select the sorting order of the result. You can choose between Ascending (default) or Descending.
</td></tr></tbody></table>

#### Output

The output contains the following populated JSON schema:

<pre>{
    "indicators": [
        {
            "associated_hashes": [
                {
                    "id": "",
                    "type": "",
                    "value": ""
                }
            ],
            "attributed_associations": [
                {
                    "id": "",
                    "name": "",
                    "type": ""
                }
            ],
            "first_seen": "",
            "id": "",
            "is_exclusive": "",
            "is_publishable": "",
            "last_seen": "",
            "last_updated": "",
            "misp": [
                {
                    "misp_id": "",
                    "detected": ""
                }
            ],
            "mscore": "",
            "sources": [
                {
                    "category": [],
                    "first_seen": "",
                    "last_seen": "",
                    "osint": "",
                    "source_name": ""
                }
            ],
            "type": "",
            "value": "",
            "reports": [
                {
                    "report_id": "",
                    "title": "",
                    "type": "",
                    "published_date": ""
                }
            ],
            "campaigns": [
                {
                    "id": "",
                    "name": "",
                    "title": ""
                }
            ]
        }
    ],
    "next": ""
}</pre>

### operation: Get Indicator Details

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Indicator Value</td><td>Specify the value of the indicator to look up. It can be URL, domain name, IP address, or file hash.
</td></tr></tbody></table>

#### Output

The output contains the following populated JSON schema:

<pre>{
    "indicators": [
        {
            "associated_hashes": [
                {
                    "id": "",
                    "type": "",
                    "value": ""
                }
            ],
            "attributed_associations": [
                {
                    "id": "",
                    "name": "",
                    "type": ""
                }
            ],
            "first_seen": "",
            "id": "",
            "is_exclusive": "",
            "is_publishable": "",
            "last_seen": "",
            "last_updated": "",
            "misp": [
                {
                    "misp_id": "",
                    "detected": ""
                }
            ],
            "mscore": "",
            "sources": [
                {
                    "category": [],
                    "first_seen": "",
                    "last_seen": "",
                    "osint": "",
                    "source_name": ""
                }
            ],
            "type": "",
            "value": "",
            "reports": [
                {
                    "report_id": "",
                    "title": "",
                    "type": "",
                    "published_date": ""
                }
            ],
            "campaigns": [
                {
                    "id": "",
                    "name": "",
                    "title": ""
                }
            ]
        }
    ]
}</pre>

### operation: Get Threat Actors List

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Limit</td><td>Specify the maximum number of results, per page, that this operation should return. By default, this option is set as 25 and maximum allowed 1000
</td></tr><tr><td>Offset</td><td>Index of the first item to be returned by this operation. This parameter is useful for pagination and for getting a subset of items. By default, this is set as 0.
</td></tr></tbody></table>

#### Output

The output contains the following populated JSON schema:

<pre>{
    "threat-actors": [
        {
            "aliases": [
                {
                    "attribution_scope": "",
                    "name": ""
                }
            ],
            "description": "",
            "id": "",
            "intel_free": "",
            "last_updated": "",
            "name": ""
        }
    ],
    "total_count": ""
}</pre>

### operation: Get Threat Actor Details

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Actor ID/Name</td><td>Specify the ID or name of the actor based on which you want to retrieve actor details from Mandiant Advantage Threat Intelligence.
</td></tr></tbody></table>

#### Output

The output contains the following populated JSON schema:

<pre>{
    "aliases": [
        {
            "attribution_scope": "",
            "name": ""
        }
    ],
    "associated_uncs": [
        {
            "attribution_scope": "",
            "id": "",
            "name": ""
        }
    ],
    "audience": [
        {
            "license": "",
            "name": ""
        }
    ],
    "counts": {
        "aliases": "",
        "associated_uncs": "",
        "attack_patterns": "",
        "cve": "",
        "industries": "",
        "malware": "",
        "reports": ""
    },
    "cve": [
        {
            "attribution_scope": "",
            "cve_id": "",
            "id": ""
        }
    ],
    "description": "",
    "id": "",
    "industries": [
        {
            "attribution_scope": "",
            "id": "",
            "name": ""
        }
    ],
    "intel_free": "",
    "is_publishable": "",
    "last_activity_time": "",
    "last_updated": "",
    "locations": {
        "source": [
            {
                "country": {
                    "attribution_scope": "",
                    "id": "",
                    "iso2": "",
                    "name": ""
                },
                "region": {
                    "attribution_scope": "",
                    "id": "",
                    "name": ""
                },
                "sub_region": {
                    "attribution_scope": "",
                    "id": "",
                    "name": ""
                }
            }
        ],
        "target": [
            {
                "attribution_scope": "",
                "id": "",
                "iso2": "",
                "name": "",
                "region": "",
                "sub-region": ""
            }
        ],
        "target_region": [
            {
                "attribution_scope": "",
                "id": "",
                "key": "",
                "name": ""
            }
        ],
        "target_sub_region": [
            {
                "attribution_scope": "",
                "id": "",
                "key": "",
                "name": "",
                "region": ""
            }
        ]
    },
    "malware": [
        {
            "attribution_scope": "",
            "id": "",
            "name": ""
        }
    ],
    "motivations": [
        {
            "attribution_scope": "",
            "id": "",
            "name": ""
        }
    ],
    "name": "",
    "observed": [
        {
            "attribution_scope": "",
            "earliest": "",
            "recent": ""
        }
    ],
    "suspected_attribution": [
        {
            "attribution_scope": "",
            "id": "",
            "name": "",
            "suspected_date": ""
        }
    ],
    "tools": [
        {
            "attribution_scope": "",
            "id": "",
            "name": ""
        }
    ],
    "type": ""
}</pre>

### operation: Get Malware Families List

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Limit</td><td>Specify the maximum number of results, per page, that this operation should return. By default, this option is set as 5000.
</td></tr><tr><td>Offset</td><td>Index of the first item to be returned by this operation. This parameter is useful for pagination and for getting a subset of items. By default, this is set as 0.
</td></tr></tbody></table>

#### Output

The output contains the following populated JSON schema:

<pre>{
    "malware": [
        {
            "aliases": [
                {
                    "name": ""
                }
            ],
            "description": "",
            "has_yara": "",
            "id": "",
            "intel_free": "",
            "last_updated": "",
            "name": ""
        }
    ],
    "total_count": ""
}</pre>

### operation: Get Malware Family Details

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Malware ID/Name</td><td>Specify the ID or name of the malware based on which you want to retrieve malware details from Mandiant Advantage Threat Intelligence.
</td></tr></tbody></table>

#### Output

The output contains the following populated JSON schema:

<pre>{
    "actors": [
        {
            "country_name": "",
            "id": "",
            "iso2": "",
            "name": ""
        }
    ],
    "aliases": [
        {
            "name": ""
        }
    ],
    "audience": [
        {
            "license": "",
            "name": ""
        }
    ],
    "capabilities": [
        {
            "description": "",
            "name": ""
        }
    ],
    "counts": {
        "actors": "",
        "aliases": "",
        "attack_patterns": "",
        "capabilities": "",
        "cve": "",
        "detections": "",
        "industries": "",
        "malware": "",
        "reports": ""
    },
    "cve": [
        {
            "cve_id": "",
            "id": ""
        }
    ],
    "description": "",
    "detections": [],
    "id": "",
    "industries": [
        {
            "id": "",
            "name": ""
        }
    ],
    "intel_free": "",
    "is_publishable": "",
    "last_activity_time": "",
    "last_updated": "",
    "malware": [
        {
            "id": "",
            "name": ""
        }
    ],
    "name": "",
    "operating_systems": [],
    "roles": [],
    "type": "",
    "yara": [
        {
            "id": "",
            "name": ""
        }
    ]
}</pre>

### operation: Get Campaigns List

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Start DateTime</td><td>Select the DateTime using which you want to filter the result set to only include only those items that have been created after the specified timestamp.
</td></tr><tr><td>End DateTime</td><td>Select the DateTime using which you want to filter the result set to only include only those items that have been created before the specified timestamp.
</td></tr><tr><td>Limit</td><td>Specify the maximum number of results, per page, that this operation should return. By default, this option is set as 1000 and maximum allowed 10000.
</td></tr><tr><td>Offset</td><td>Index of the first item to be returned by this operation. This parameter is useful for pagination and for getting a subset of items. By default, this is set as 0.
</td></tr></tbody></table>

#### Output

The output contains the following populated JSON schema:

<pre>{
    "campaigns": [
        {
            "id": "",
            "name": "",
            "profile_updated": "",
            "short_name": ""
        }
    ]
}</pre>

### operation: Get Campaign Details

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Campaign ID</td><td>Specify the ID of the campaign based on which you want to retrieve campaign details from Mandiant Advantage Threat Intelligence.
</td></tr></tbody></table>

#### Output

The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "name": "",
    "description": "",
    "created": "",
    "last_updated": "",
    "last_activity_time": "",
    "audience": [
        {
            "name": "",
            "license": ""
        }
    ],
    "intel_free": "",
    "aliases": [
        {
            "name": "",
            "attribution_scope": ""
        }
    ],
    "industries": [
        {
            "id": "",
            "name": ""
        }
    ],
    "malware": [
        {
            "id": "",
            "name": "",
            "attribution_scope": ""
        }
    ],
    "vulnerabilities": [
        {
            "id": "",
            "cve_id": "",
            "attribution_scope": ""
        }
    ],
    "target_locations": {
        "source": [
            {
                "region": {
                    "id": "",
                    "name": "",
                    "attribution_scope": ""
                },
                "sub_region": {
                    "id": "",
                    "name": "",
                    "attribution_scope": ""
                },
                "country": {
                    "id": "",
                    "name": "",
                    "iso2": ""
                }
            }
        ],
        "target": [
            {
                "id": "",
                "name": "",
                "iso2": ""
            }
        ]
    },
    "campaign_type": "",
    "counts": {
        "actors": "",
        "reports": "",
        "malware": "",
        "campaigns": "",
        "attack_patterns": "",
        "industries": "",
        "timeline": "",
        "vulnerabilities": "",
        "actor_collaborations": "",
        "tools": ""
    }
}</pre>

### operation: Get Vulnerabilities List

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Start DateTime</td><td>Select the DateTime using which you want to filter the result set to only include only those items that have been created after the specified timestamp.
</td></tr><tr><td>End DateTime</td><td>Select the DateTime using which you want to filter the result set to only include only those items that have been created before the specified timestamp.
</td></tr><tr><td>Limit</td><td>Specify the maximum number of results, per page, that this operation should return. By default, this option is set as 50 and maximum allowed 1000.
</td></tr><tr><td>Skip Token</td><td>Skiptoken is only used if a previous operation returned a partial result. If a previous response contains a next element, the value of the next element will include a skiptoken parameter that specifies a starting point to use for subsequent calls. When using next no other parameters should be included in the request. Note: The token returned is valid for 10 minutes.
</td></tr><tr><td>Sort By</td><td>Specify the name of the field based on which you want to sort the result (vulnerabilities) retrieved by this operation. It can also be extended to support sort order by appending a ':' and sort order.
</td></tr><tr><td>Sort Order</td><td>Select the sorting order of the result. You can choose between Ascending (default) or Descending.
</td></tr><tr><td>Rating Types</td><td>Select the one or more types of desired rating based on which you want to retrieve campaign details from Mandiant Advantage Threat Intelligence. You can choose from the following options: Analyst, Predicted, and Unrated.
</td></tr><tr><td>Risk Ratings</td><td>Select the one or more risk ratings based on which you want to retrieve campaign details from Mandiant Advantage Threat Intelligence. You can choose from the following options: Critical, High, Medium, Low, and Unrated.
</td></tr></tbody></table>

#### Output

The output contains the following populated JSON schema:

<pre>{
    "next": "",
    "total_count": "",
    "vulnerability": [
        {
            "common_vulnerability_scores": {
                "v2.0": {
                    "access_complexity": "",
                    "access_vector": "",
                    "authentication": "",
                    "availability_impact": "",
                    "base_score": "",
                    "confidentiality_impact": "",
                    "integrity_impact": "",
                    "remediation_level": "",
                    "temporal_score": "",
                    "vector_string": "",
                    "exploitability": "",
                    "report_confidence": ""
                },
                "v3.1": {
                    "attack_complexity": "",
                    "attack_vector": "",
                    "availability_impact": "",
                    "base_score": "",
                    "confidentiality_impact": "",
                    "exploit_code_maturity": "",
                    "integrity_impact": "",
                    "privileges_required": "",
                    "remediation_level": "",
                    "report_confidence": "",
                    "scope": "",
                    "temporal_score": "",
                    "user_interaction": "",
                    "vector_string": ""
                }
            },
            "cve_id": "",
            "description": "",
            "exploitation_state": "",
            "id": "",
            "intel_free": "",
            "is_predicted": "",
            "observed_in_the_wild": "",
            "publish_date": "",
            "risk_rating": "",
            "sources": [
                {
                    "url": "",
                    "date": "",
                    "is_vendor_fix": "",
                    "source_description": "",
                    "source_name": "",
                    "unique_id": ""
                }
            ],
            "vulnerable_cpes": [
                {
                    "cpe": "",
                    "cpe_title": "",
                    "technology_name": "",
                    "vendor_name": ""
                }
            ],
            "was_zero_day": ""
        }
    ]
}</pre>

### operation: Get Reports List

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Start DateTime</td><td>Select the DateTime using which you want to filter the result set to only include only those items that have been created after the specified timestamp.
</td></tr><tr><td>End DateTime</td><td>Select the DateTime using which you want to filter the result set to only include only those items that have been created before the specified timestamp.
</td></tr><tr><td>Limit</td><td>Specify the maximum number of results, per page, that this operation should return. By default, this option is set as 25 and maximum allowed 1000.
</td></tr><tr><td>Offset</td><td>Index of the first item to be returned by this operation. This parameter is useful for pagination and for getting a subset of items. By default, this is set as 0.
</td></tr><tr><td>Skip Token</td><td>Skiptoken is only used if a previous operation returned a partial result. If a previous response contains a next element, the value of the next element will include a skiptoken parameter that specifies a starting point to use for subsequent calls. When using next no other parameters should be included in the request. Note: The token returned is valid for 10 minutes.
</td></tr></tbody></table>

#### Output

The output contains the following populated JSON schema:

<pre>{
    "next": "",
    "objects": [
        {
            "audience": [],
            "id": "",
            "intelligence_type": "",
            "publish_date": "",
            "report_id": "",
            "report_link": "",
            "report_type": "",
            "title": "",
            "version": "",
            "version_one_publish_date": "",
            "threat_scape": []
        }
    ],
    "total_count": ""
}</pre>

### operation: Get Report Details

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Report ID</td><td>Specify the ID of the report based on which you want to retrieve report details from Mandiant Advantage Threat Intelligence.
</td></tr></tbody></table>

#### Output

The output contains the following populated JSON schema:

<pre>{
    "audience": [],
    "cvss_base_score": "",
    "cvss_temporal_score": "",
    "executive_summary": "",
    "files": [
        {
            "actor": "",
            "identifier": "",
            "malwareFamily": "",
            "md5": "",
            "name": "",
            "sha1": "",
            "sha256": "",
            "size": "",
            "type": ""
        }
    ],
    "id": "",
    "in_the_wild": "",
    "previous_versions": [
        {
            "publish_date": "",
            "report_id": "",
            "version_number": ""
        }
    ],
    "publish_date": "",
    "relations": {},
    "report_confidence": "",
    "report_id": "",
    "report_type": "",
    "requester_org_id": "",
    "tags": {
        "actors": [
            {
                "aliases": [],
                "id": "",
                "name": ""
            }
        ],
        "affected_industries": [],
        "affected_systems": [],
        "intended_effects": [],
        "malware_families": [
            {
                "aliases": [],
                "id": "",
                "name": ""
            }
        ],
        "motivations": [],
        "source_geographies": [],
        "target_geographies": [],
        "targeted_informations": [],
        "ttps": []
    },
    "threat_detail": "",
    "threat_scape": [],
    "title": "",
    "version": "",
    "version_one_publish_date": "",
    "zero_day": ""
}</pre>

## Included playbooks

The `Sample - mandiant-advantage-threat-intelligence - 1.0.0` playbook collection comes bundled with the Mandiant Advantage Threat Intelligence connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR&trade; after importing the Mandiant Advantage Threat Intelligence connector.

- Get Campaign Details
- Get Campaigns List
- Get Indicator Details
- Get Indicators List
- Get Malware Families List
- Get Malware Family Details
- Get Report Details
- Get Reports List
- Get Threat Actor Details
- Get Threat Actors List
- Get Vulnerabilities List

**Note**: If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection since the sample playbook collection gets deleted during connector upgrade and delete.
