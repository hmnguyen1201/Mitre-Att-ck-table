# Mitre Att&ck detection coverage tracking with Kibana

[Elastic SIEM app](https://www.elastic.co/siem) comes with many built-in detections that can be found in [this](https://github.com/elastic/detection-rules) open github repository and they all come with at least one Mitre Att&ck technique and one tactic. To read more about Mitre Att&ck framework click [here](https://attack.mitre.org/)


It is critical to know what detection gaps you have in your environment. This visualization can help you identify your gaps a little better so that you can better allocate your time and effort to create the detections accordingly. The article is going to walk you through the process how to get this visualization built in your Kibana for better detection coverage visibility.

### Step 1: Identify where the Elastic Signals metadata can be found in Elastic. 
  - The Elastic Signals information can be found in **.kibana** system index with query below:
  ```
GET .kibana/_search
{
    "query": {
    "bool": {
      "must": [],
      "filter": [
        {
          "match_all": {}
        },
        {
          "exists": {
            "field": "alert.name.keyword"
          }
        }
      ],
      "should": [],
      "must_not": []
    }
  }
}
````

- A challenge with this sub-dataset being stored in **.kibana** index is that some of the fields we need for the visualization are not indexed/mapped. Hence step 2.

### Step 2: Copy the Elastic signal metadata out to a different index using Elastic [Reindex API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html)

```
POST _reindex
{
  "source": {
    "index": ".kibana",
    "query": {
      "bool": {
        "must": [],
        "filter": [
          {
            "match_all": {}
          },
          {
            "exists": {
              "field": "alert.name.keyword"
            }
          }
        ],
        "should": [],
        "must_not": []
      }
    }
  },
  "dest": {
    "index": "kibana-detections",
    "version_type": "external"
  }
}
```
- This API request queries the data in .kibana and send that to a new index called **kibana-detections**. Setting version_type to external causes Elasticsearch to preserve the version from the source, create any documents that are missing, and update any documents that have an older version in the destination than they do in the source. However, you want to automate this process so you will always have the most up to date information about your detections state. Hence step 3.


### Step 3: Automate the reindex process with watcher or any script with cronjob
```
{
  "trigger": {
    "schedule": {
      "interval": "5m"
    }
  },
  "input": {
    "http": {
      "request": {
        "scheme": "https",
        "host": "<your Elasticsearch URL>",
        "port": 9200,
        "method": "post",
        "path": "/_reindex",
        "params": {},
        "headers": {},
        "auth": {
          "basic": {
            "username": "elastic",
            "password": "::es_redacted::"
          }
        },
        "body": """{"source": {"index": ".kibana","query": {"bool": {"must": [],"filter": [{"match_all": {}},{"exists": {"field": "alert.name.keyword"}}],"should": [],"must_not": []}}},"dest": {"index": "kibana-detections","version_type": "external"}}"""
      }
    }
  },
  "condition": {
    "always": {}
  },
  "actions": {
    "my-logging-action": {
      "logging": {
        "level": "info",
        "text": "Finished reindex detections"
      }
    }
  }
}

```

- Once the reindex API is executed successfully, you should have a new index called `kibana-detections` with all the fields being mapped using default Elastic dynamic mapping and it is good enough for us to proceed to step 5.

### Step 5:  Create the Vega visualization
- In Kibana --> Visualization --> Create visualization --> Custom visualization and paste the code below and enjoy
- To make the cells are clickable and take you to your kibana saved search that display the details of the Kibana alerts, make sure to replace https://kibana_Link with your actual kibana link in the vega code. 

```
{
  "$schema": "https://vega.github.io/schema/vega/v5.json",
  "description": "A basic bar chart example, with value labels shown upon mouse hover.",
  "autosize": "pad",
  "data": [
    {
      "name": "agg_value",
      "url": {
        "index": "kibana-detections",
        "%context%": true,
        "body": {
          "aggs": {
            "AllTactics": {
              "terms": {
                "field": "alert.params.threat.tactic.name.keyword",
                "size": 100
              },
              "aggs": {
                "AllTechniques": {
                  "terms": {
                    "field": "alert.params.threat.technique.name.keyword",
                    "size": 100
                  }
                }
              }
            }
          },
          "size": 0
        }
      },
      "format": {"property": "aggregations.AllTactics.buckets"},
      "transform": [
        {"type": "formula", "expr": "datum.AllTechniques", "as": ["buckets"]},
        {"type": "flatten", "fields": ["buckets.buckets"], "as": ["results"]}
      ]
    },
    {
      "name": "table",
      "values": [
        {
          "category": "Collection",
          "technique": "Archive Collected Data",
          "position": 1
        },
        {"category": "Collection", "technique": "Audio Capture", "position": 2},
        {
          "category": "Collection",
          "technique": "Automated Collection",
          "position": 3
        },
        {
          "category": "Collection",
          "technique": "Clipboard Data",
          "position": 4
        },
        {
          "category": "Collection",
          "technique": "Clipboard Data",
          "position": 5
        },
        {
          "category": "Collection",
          "technique": "Data from Information Repositories",
          "position": 6
        },
        {
          "category": "Collection",
          "technique": "Data from Local System",
          "position": 7
        },
        {
          "category": "Collection",
          "technique": "Data from Network Shared Drive",
          "position": 8
        },
        {
          "category": "Collection",
          "technique": "Data from Removable Media",
          "position": 9
        },
        {"category": "Collection", "technique": "Data Staged", "position": 10},
        {
          "category": "Collection",
          "technique": "Email Collection",
          "position": 11
        },
        {
          "category": "Collection",
          "technique": "Input Capture",
          "position": 12
        },
        {
          "category": "Collection",
          "technique": "Man in the Browser",
          "position": 13
        },
        {
          "category": "Collection",
          "technique": "Man-in-the-Middle",
          "position": 14
        },
        {
          "category": "Collection",
          "technique": "Screen Capture",
          "position": 15
        },
        {
          "category": "Collection",
          "technique": "Video Capture",
          "position": 16
        },
        {
          "category": "Command and Control",
          "technique": "Application Layer Protocol",
          "position": 1
        },
        {
          "category": "Command and Control",
          "technique": "Communication Through Removable Media",
          "position": 2
        },
        {
          "category": "Command and Control",
          "technique": "Data Encoding",
          "position": 3
        },
        {
          "category": "Command and Control",
          "technique": "Data Obfuscation",
          "position": 4
        },
        {
          "category": "Command and Control",
          "technique": "Dynamic Resolution",
          "position": 5
        },
        {
          "category": "Command and Control",
          "technique": "Encrypted Channel",
          "position": 6
        },
        {
          "category": "Command and Control",
          "technique": "Fallback Channels",
          "position": 7
        },
        {
          "category": "Command and Control",
          "technique": "Multi-Stage Channels",
          "position": 8
        },
        {
          "category": "Command and Control",
          "technique": "Ingress Tool Transfer",
          "position": 9
        },
        {
          "category": "Command and Control",
          "technique": "Non-Application Layer Protocol",
          "position": 10
        },
        {
          "category": "Command and Control",
          "technique": "Non-Standard Port",
          "position": 11
        },
        {
          "category": "Command and Control",
          "technique": "Protocol Tunneling",
          "position": 12
        },
        {
          "category": "Command and Control",
          "technique": "Proxy",
          "position": 13
        },
        {
          "category": "Command and Control",
          "technique": "Remote Access Software",
          "position": 14
        },
        {
          "category": "Command and Control",
          "technique": "Proxy",
          "position": 15
        },
        {
          "category": "Command and Control",
          "technique": "Traffic Signaling",
          "position": 16
        },
        {
          "category": "Command and Control",
          "technique": "Web Service",
          "position": 17
        },
        {
          "category": "Credential Access",
          "technique": "Brute Force",
          "position": 1
        },
        {
          "category": "Credential Access",
          "technique": "Credentials from Password Stores",
          "position": 2
        },
        {
          "category": "Credential Access",
          "technique": "Exploitation for Credential Access",
          "position": 3
        },
        {
          "category": "Credential Access",
          "technique": "Forced Authentication",
          "position": 4
        },
        {
          "category": "Credential Access",
          "technique": "Input Capture",
          "position": 5
        },
        {
          "category": "Credential Access",
          "technique": "Man-in-the-Middle",
          "position": 6
        },
        {
          "category": "Credential Access",
          "technique": "Modify Authentication Process",
          "position": 7
        },
        {
          "category": "Credential Access",
          "technique": "Network Sniffing",
          "position": 8
        },
        {
          "category": "Credential Access",
          "technique": "OS Credential Dumping",
          "position": 9
        },
        {
          "category": "Credential Access",
          "technique": "Steal or Forge Kerberos Tickets",
          "position": 10
        },
        {
          "category": "Credential Access",
          "technique": "Steal Web Session Cookie",
          "position": 11
        },
        {
          "category": "Credential Access",
          "technique": "Two-Factor Authentication Interception",
          "position": 12
        },
        {
          "category": "Credential Access",
          "technique": "Unsecured Credentials",
          "position": 13
        },
        {
          "category": "Defense Evasion",
          "technique": "Abuse Elevation Control Mechanism",
          "position": 1
        },
        {
          "category": "Defense Evasion",
          "technique": "Access Token Manipulation",
          "position": 2
        },
        {
          "category": "Defense Evasion",
          "technique": "BITS Jobs",
          "position": 3
        },
        {
          "category": "Defense Evasion",
          "technique": "Deobfuscate/Decode Files or Information",
          "position": 4
        },
        {
          "category": "Defense Evasion",
          "technique": "Direct Volume Access",
          "position": 5
        },
        {
          "category": "Defense Evasion",
          "technique": "Execution Guardrails",
          "position": 6
        },
        {
          "category": "Defense Evasion",
          "technique": "Exploitation for Defense Evasion",
          "position": 7
        },
        {
          "category": "Defense Evasion",
          "technique": "File and Directory Permissions Modification",
          "position": 8
        },
        {
          "category": "Defense Evasion",
          "technique": "Group Policy Modification",
          "position": 9
        },
        {
          "category": "Defense Evasion",
          "technique": "Hide Artifacts",
          "position": 10
        },
        {
          "category": "Defense Evasion",
          "technique": "Hijack Execution Flow",
          "position": 11
        },
        {
          "category": "Defense Evasion",
          "technique": "Impair Defenses",
          "position": 12
        },
        {
          "category": "Defense Evasion",
          "technique": "Indicator Removal on Host",
          "position": 13
        },
        {
          "category": "Defense Evasion",
          "technique": "Indirect Command Execution",
          "position": 14
        },
        {
          "category": "Defense Evasion",
          "technique": "Masquerading",
          "position": 15
        },
        {
          "category": "Defense Evasion",
          "technique": "Modify Authentication Process",
          "position": 16
        },
        {
          "category": "Defense Evasion",
          "technique": "Modify Registry",
          "position": 17
        },
        {
          "category": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "position": 18
        },
        {
          "category": "Defense Evasion",
          "technique": "Pre-OS Boot",
          "position": 19
        },
        {
          "category": "Defense Evasion",
          "technique": "Process Injection",
          "position": 20
        },
        {
          "category": "Defense Evasion",
          "technique": "Rogue Domain Controller",
          "position": 21
        },
        {"category": "Defense Evasion", "technique": "Rootkit", "position": 22},
        {
          "category": "Defense Evasion",
          "technique": "Signed Binary Proxy Execution",
          "position": 23
        },
        {
          "category": "Defense Evasion",
          "technique": "Signed Script Proxy Execution",
          "position": 24
        },
        {
          "category": "Defense Evasion",
          "technique": "Subvert Trust Controls",
          "position": 25
        },
        {
          "category": "Defense Evasion",
          "technique": "Template Injection",
          "position": 26
        },
        {
          "category": "Defense Evasion",
          "technique": "Traffic Signaling",
          "position": 27
        },
        {
          "category": "Defense Evasion",
          "technique": "Trusted Developer Utilities Proxy Execution",
          "position": 28
        },
        {
          "category": "Defense Evasion",
          "technique": "Use Alternate Authentication Material",
          "position": 29
        },
        {
          "category": "Defense Evasion",
          "technique": "Valid Accounts",
          "position": 30
        },
        {
          "category": "Defense Evasion",
          "technique": "Virtualization/Sandbox Evasion",
          "position": 31
        },
        {
          "category": "Discovery",
          "technique": "Account Discovery",
          "position": 1
        },
        {
          "category": "Discovery",
          "technique": "Application Window Discovery",
          "position": 2
        },
        {
          "category": "Discovery",
          "technique": "Browser Bookmark Discovery",
          "position": 3
        },
        {
          "category": "Discovery",
          "technique": "Domain Trust Discovery",
          "position": 4
        },
        {
          "category": "Discovery",
          "technique": "File and Directory Discovery",
          "position": 5
        },
        {
          "category": "Discovery",
          "technique": "Network Service Scanning",
          "position": 6
        },
        {
          "category": "Discovery",
          "technique": "Network Share Discovery",
          "position": 7
        },
        {
          "category": "Discovery",
          "technique": "Network Sniffing",
          "position": 8
        },
        {
          "category": "Discovery",
          "technique": "Password Policy Discovery",
          "position": 9
        },
        {
          "category": "Discovery",
          "technique": "Peripheral Device Discovery",
          "position": 10
        },
        {
          "category": "Discovery",
          "technique": "Permission Groups Discovery",
          "position": 11
        },
        {
          "category": "Discovery",
          "technique": "Process Discovery",
          "position": 12
        },
        {
          "category": "Discovery",
          "technique": "Query Registry",
          "position": 13
        },
        {
          "category": "Discovery",
          "technique": "Remote System Discovery",
          "position": 14
        },
        {
          "category": "Discovery",
          "technique": "Software Discovery",
          "position": 15
        },
        {
          "category": "Discovery",
          "technique": "System Information Discovery",
          "position": 16
        },
        {
          "category": "Discovery",
          "technique": "System Network Configuration Discovery",
          "position": 17
        },
        {
          "category": "Discovery",
          "technique": "System Network Connections Discovery",
          "position": 18
        },
        {
          "category": "Discovery",
          "technique": "System Owner/User Discovery",
          "position": 19
        },
        {
          "category": "Discovery",
          "technique": "System Service Discovery",
          "position": 20
        },
        {
          "category": "Discovery",
          "technique": "System Time Discovery",
          "position": 21
        },
        {
          "category": "Discovery",
          "technique": "Virtualization/Sandbox Evasion",
          "position": 22
        },
        {
          "category": "Execution",
          "technique": "Command and Scripting Interpreter",
          "position": 1
        },
        {
          "category": "Execution",
          "technique": "Exploitation for Client Execution",
          "position": 2
        },
        {
          "category": "Execution",
          "technique": "Inter-Process Communication",
          "position": 3
        },
        {"category": "Execution", "technique": "Native API", "position": 4},
        {
          "category": "Execution",
          "technique": "Scheduled Task/Job",
          "position": 5
        },
        {"category": "Execution", "technique": "Shared Modules", "position": 6},
        {
          "category": "Execution",
          "technique": "Software Deployment Tools",
          "position": 7
        },
        {
          "category": "Execution",
          "technique": "System Services",
          "position": 8
        },
        {"category": "Execution", "technique": "User Execution", "position": 9},
        {
          "category": "Execution",
          "technique": "Windows Management Instrumentation",
          "position": 10
        }
      ],
      "transform": [
        {
          "type": "lookup",
          "from": "agg_value",
          "key": "results.key",
          "fields": ["technique"],
          "values": ["results.doc_count", "results.key"],
          "as": ["detection_count", "detection_name"],
          "default": 0
        },
        {
          "type": "formula",
          "expr": "datum.technique + ' : ' + datum.detection_count",
          "as": "full_string"
        },
        {"type" : "formula", "expr":"'https://kibana_Link/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-24h,to:now))&_a=(columns:!(alert.params.index,alert.name,alert.params.description,alert.params.query),filters:!((%27$state%27:(store:appState),meta:(alias:!n,disabled:!f,index:acbc4480-4aa9-11eb-8bc4-e57bebeb595d,key:alert.params.threat.technique.name,negate:!f,params:(query:%27%27),type:phrase),query:(match_phrase:(alert.params.threat.technique.name:%27' + datum.technique + '%27)))),index:acbc4480-4aa9-11eb-8bc4-e57bebeb595d,interval:auto,query:(language:kuery,query:%27%27),sort:!())'","as": "thelink"}
      ]
    }
  ],
  "scales": [
    {
      "name": "xscale",
      "type": "band",
      "domain": {"data": "table", "field": "category"},
      "range": {"step": 250}
    },
    {
      "name": "yscale",
      "type": "band",
      "domain": {"data": "table", "field": "position"},
      "range": {"step": 50}
    },
    {
      "name": "color",
      "type": "linear",
      "domain": [0, 10],
      "range": ["#ffffff", " #9cfb48"]
    }
  ],
  "legends": [
    {
      "fill": "color"
    }
  ],
  "signals": [],
  "axes": [
    {
      "orient": "top",
      "scale": "xscale",
      "ticks": true,
      "grid": false,
      "offset": {"value": 50},
      "labelAlign": "right",
      "labelColor": "blue"
    }
  ],
  "marks": [
    {
      "type": "rect",
      "from": {"data": "table"},
      "encode": {
        "enter": {
          "width": {"scale": "xscale", "band": 1},
          "height": {"value": -50},
          "x": {"scale": "xscale", "field": "category"},
          "y": {"scale": "yscale", "field": "position"},
          "strokeWidth": {"value": 2},
          "cornerRadius": {"value": 3.1},
          "fill": {"scale": "color", "field": "detection_count"},
          "stroke": {"value": "#652c90"},
          "tooltip": {"signal": "{'Detection Count': datum.detection_count}"},
          "href": {"field": "thelink", "type": "nominal"}
        }
      }
    },
    {
      "type": "text",
      "from": {"data": "table"},
      "encode": {
        "enter": {
          "x": {"scale": "xscale", "field": "category"},
          "width": {"scale": "xscale", "band": 1},
          "dx": {"value": 15},
          "dy": {"value": -15},
          "fontSize": {"value": 14},
          "fontStyle": {"value": "italic"},
          "fontWeight": {"value": "bold"},
          "tooltip": {"signal": "{'Detection Count': datum.detection_count}"},
          "y": {"scale": "yscale", "field": "position"},
          "text": {"field": "full_string"},
          "limit": {"value": 240},
          "href": {"field": "thelink", "type": "nominal"}
        }
      }
    }
  ]
}
  ```


Ready to get started? Sign up for a [free trial of Elastic Cloud](https://www.elastic.co/cloud/), learn more about [Vega Visualization](https://www.elastic.co/webinars/vega-plugin-custom-visualizations-with-kibana), and please reach out on the [discuss forums](https://discuss.elastic.co/) if you have any questions.

