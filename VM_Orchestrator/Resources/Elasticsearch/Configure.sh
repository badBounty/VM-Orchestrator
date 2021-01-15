##Resources index creation
curl -X PUT "localhost:9200/resources?pretty"

curl -X PUT "localhost:9200/resources/_mapping?pretty" -H 'Content-Type: application/json' -d'
{
  "properties": {
    "resource_additional_info": {
      "properties": {
        "resource_asn": {
          "type": "keyword"
        },

        "resource_city": {
          "type": "keyword"
        },

        "resource_country": {
          "type": "keyword"
        },

        "resource_geoloc": {
          "type": "geo_point"
        },

        "resource_isp": {
          "type": "keyword"
        },

        "resource_org": {
          "type": "keyword"
        },

        "resource_region": {
          "type": "keyword"
        }
      }
    },

    "resource_asset_value": {
      "type": "long"
    },

    "resource_domain": {
      "type": "keyword"
    },

    "resource_exposition": {
      "type": "long"
    },

    "resource_first_seen": {
      "type": "date"
    },

    "resource_has_urls": {
      "type": "keyword"
    },

    "resource_id": {
      "type": "keyword"
    },

    "resource_ip": {
      "type": "keyword"
    },

    "resource_is_alive": {
      "type": "boolean"
    },

    "resource_last_seen": {
      "type": "date"
    },

    "resource_nmap_information": {
      "properties": {
        "@portid": {
          "type": "keyword"
        },

        "@protocol": {
          "type": "keyword"
        },

        "service": {
          "properties": {
            "@conf": {
              "type": "keyword"
            },

            "@devicetype": {
              "type": "text",

              "fields": {
                "keyword": {
                  "type": "keyword",

                  "ignore_above": 256
                }
              }
            },

            "@extrainfo": {
              "type": "keyword"
            },

            "@method": {
              "type": "keyword"
            },

            "@name": {
              "type": "keyword"
            },

            "@ostype": {
              "type": "text",

              "fields": {
                "keyword": {
                  "type": "keyword",

                  "ignore_above": 256
                }
              }
            },

            "@product": {
              "type": "keyword"
            },

            "@servicefp": {
              "type": "text",

              "fields": {
                "keyword": {
                  "type": "keyword",

                  "ignore_above": 256
                }
              }
            },

            "@tunnel": {
              "type": "text",

              "fields": {
                "keyword": {
                  "type": "keyword",

                  "ignore_above": 256
                }
              }
            },

            "@version": {
              "type": "text",

              "fields": {
                "keyword": {
                  "type": "keyword",

                  "ignore_above": 256
                }
              }
            },

            "cpe": {
              "type": "text",

              "fields": {
                "keyword": {
                  "type": "keyword",

                  "ignore_above": 256
                }
              }
            }
          }
        },

        "state": {
          "properties": {
            "@reason": {
              "type": "text",

              "fields": {
                "keyword": {
                  "type": "keyword",

                  "ignore_above": 256
                }
              }
            },

            "@reason_ttl": {
              "type": "text",

              "fields": {
                "keyword": {
                  "type": "keyword",

                  "ignore_above": 256
                }
              }
            },

            "@state": {
              "type": "text",

              "fields": {
                "keyword": {
                  "type": "keyword",

                  "ignore_above": 256
                }
              }
            }
          }
        }
      }
    },

    "resource_priority": {
      "type": "long"
    },

    "resource_responsive_urls": {
      "type": "keyword"
    },

    "resource_scanned": {
      "type": "boolean"
    },

    "resource_subdomain": {
      "type": "keyword"
    },

    "resource_type": {
      "type": "keyword"
    }
  }
}
'

##web_vulnerabilities index creation
curl -X PUT "localhost:9200/web_vulnerabilities?pretty"

curl -X PUT "localhost:9200/web_vulnerabilities/_mapping?pretty" -H 'Content-Type: application/json' -d'
{
  "properties": {
    "vulnerability_cvss3_severity": {
      "type": "keyword"
    },

    "vulnerability_cvss_score": {
      "type": "long"
    },

    "vulnerability_date_found": {
      "type": "date"
    },

    "vulnerability_domain": {
      "type": "keyword"
    },

    "vulnerability_extra_info": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "vulnerability_id": {
      "type": "keyword"
    },

    "vulnerability_language": {
      "type": "keyword"
    },

    "vulnerability_last_seen": {
      "type": "date"
    },

    "vulnerability_observation": {
      "properties": {
        "vulnerability_implication": {
          "type": "text"
        },

        "vulnerability_observation_note": {
          "type": "text"
        },

        "vulnerability_observation_title": {
          "type": "keyword"
        },

        "vulnerability_recommendation_note": {
          "type": "text"
        },

        "vulnerability_recommendation_title": {
          "type": "keyword"
        },

        "vulnerability_severity": {
          "type": "keyword"
        },

        "vulnerability_title": {
          "type": "keyword"
        }
      }
    },

    "vulnerability_state": {
      "type": "keyword"
    },

    "vulnerability_subdomain": {
      "type": "keyword"
    },

    "vulnerability_vuln_type": {
      "type": "keyword"
    },

    "vulnerability_vulnerability_name": {
      "type": "keyword"
    }
  }
}
'

##infra_vulnerabilities index creation
curl -X PUT "localhost:9200/infra_vulnerabilities?pretty"

curl -X PUT "localhost:9200/infra_vulnerabilities/_mapping?pretty" -H 'Content-Type: application/json' -d'
{
  "properties": {
    "vulnerability_cvss3_severity": {
      "type": "keyword"
    },

    "vulnerability_cvss_score": {
      "type": "long"
    },

    "vulnerability_date_found": {
      "type": "date"
    },

    "vulnerability_domain": {
      "type": "keyword"
    },

    "vulnerability_extra_info": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "vulnerability_id": {
      "type": "keyword"
    },

    "vulnerability_language": {
      "type": "keyword"
    },

    "vulnerability_last_seen": {
      "type": "date"
    },

    "vulnerability_observation": {
      "properties": {
        "vulnerability_implication": {
          "type": "text"
        },

        "vulnerability_observation_note": {
          "type": "text"
        },

        "vulnerability_observation_title": {
          "type": "keyword"
        },

        "vulnerability_recommendation_note": {
          "type": "text"
        },

        "vulnerability_recommendation_title": {
          "type": "keyword"
        },

        "vulnerability_severity": {
          "type": "keyword"
        },

        "vulnerability_title": {
          "type": "keyword"
        }
      }
    },

    "vulnerability_state": {
      "type": "keyword"
    },

    "vulnerability_subdomain": {
      "type": "keyword"
    },

    "vulnerability_vuln_type": {
      "type": "keyword"
    },

    "vulnerability_vulnerability_name": {
      "type": "keyword"
    }
  }
}
'

##code_vulnerabilities index creation
curl -X PUT "localhost:9200/code_vulnerabilities?pretty"

curl -X PUT "localhost:9200/code_vulnerabilities/_mapping?pretty" -H 'Content-Type: application/json' -d'
{
  "properties": {
    "vulnerability_id": {
      "type": "keyword"
    },
    
    "vulnerability_branch" : {
      "type" : "keyword"
    },
    
    "vulnerability_title": {
      "type": "keyword"
    },

    "vulnerability_description": {
      "type": "keyword"
    },

    "vulnerability_component": {
      "type": "keyword"
    },

    "vulnerability_line": {
      "type": "keyword"
    },

    "vulnerability_affected_code": {
      "type": "keyword"
    },

    "vulnerability_first_commit": {
      "type": "keyword"
    },

    "vulnerability_last_commit": {
      "type": "keyword"
    },

    "vulnerability_username": {
      "type": "keyword"
    },

    "vulnerability_pipeline_name": {
      "type": "keyword"
    },

    "vulnerability_language": {
      "type": "keyword"
    },

    "vulnerability_hash": {
      "type": "keyword"
    },

    "vulnerability_severity_tool": {
      "type": "keyword"
    },

    "vulnerability_severity": {
      "type": "keyword"
    },

    "vulnerability_vulnerability_name": {
      "type": "keyword"
    },

    "vulnerability_observation": {
      "properties": {
        "vulnerability_implication": {
          "type": "text"
        },

        "vulnerability_observation_note": {
          "type": "text"
        },

        "vulnerability_observation_title": {
          "type": "keyword"
        },

        "vulnerability_recommendation_note": {
          "type": "text"
        },

        "vulnerability_recommendation_title": {
          "type": "keyword"
        },

        "vulnerability_severity": {
          "type": "keyword"
        }
      }
    },

    "vulnerability_first_seen": {
      "type": "date"
    },

    "vulnerability_last_seen": {
      "type": "date"
    },

    "vulnerability_vuln_type": {
      "type": "keyword"
    },

    "vulnerability_state": {
      "type": "keyword"
    }
  }
}
'

##log_resource index creation
curl -X PUT "localhost:9200/log_resource?pretty"

curl -X PUT "localhost:9200/log_resource/_mapping?pretty" -H 'Content-Type: application/json' -d'
{
  "properties": {
    "log_id": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "log_resource_domain": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "log_resource_id": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "log_resource_module_keyword": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "log_resource_subdomain": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "log_resource_timestamp": {
      "type": "date"
    }
  }
}
'

##log_module index creation
curl -X PUT "localhost:9200/log_module?pretty"

curl -X PUT "localhost:9200/log_module/_mapping?pretty" -H 'Content-Type: application/json' -d'
{
  "properties": {
    "log_id": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "log_module_arguments": {
      "properties": {
        "acunetix_scan": {
          "type": "boolean"
        },

        "burp_scan": {
          "type": "boolean"
        },

        "domain": {
          "type": "text",

          "fields": {
            "keyword": {
              "type": "keyword",

              "ignore_above": 256
            }
          }
        },

        "exposition": {
          "type": "float"
        },

        "invasive_scans": {
          "type": "boolean"
        },

        "is_first_run": {
          "type": "boolean"
        },

        "language": {
          "type": "text",

          "fields": {
            "keyword": {
              "type": "keyword",

              "ignore_above": 256
            }
          }
        },

        "nessus_scan": {
          "type": "boolean"
        },

        "priority": {
          "type": "long"
        },

        "resource": {
          "type": "text",

          "fields": {
            "keyword": {
              "type": "keyword",

              "ignore_above": 256
            }
          }
        },

        "scan_type": {
          "type": "text",

          "fields": {
            "keyword": {
              "type": "keyword",

              "ignore_above": 256
            }
          }
        },

        "target": {
          "type": "text",

          "fields": {
            "keyword": {
              "type": "keyword",

              "ignore_above": 256
            }
          }
        },

        "type": {
          "type": "text",

          "fields": {
            "keyword": {
              "type": "keyword",

              "ignore_above": 256
            }
          }
        }
      }
    },

    "log_module_domain": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "log_module_found": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "log_module_keyword": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "log_module_state": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "log_module_timestamp": {
      "type": "date"
    }
  }
}
'

##log_vuln index creation
curl -X PUT "localhost:9200/log_vuln?pretty"

curl -X PUT "localhost:9200/log_vuln/_mapping?pretty" -H 'Content-Type: application/json' -d'
{
  "properties": {
    "log_id": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "log_vulnerability_found": {
      "type": "boolean"
    },

    "log_vulnerability_id": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "log_vulnerability_module_keyword": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "log_vulnerability_name": {
      "type": "text",

      "fields": {
        "keyword": {
          "type": "keyword",

          "ignore_above": 256
        }
      }
    },

    "log_vulnerability_timestamp": {
      "type": "date"
    }
  }
}
'

curl -X POST "localhost:5601/api/saved_objects/_import" -H "kbn-xsrf: true" --form file=@code_dash.ndjson

curl -X POST "localhost:5601/api/saved_objects/_import" -H "kbn-xsrf: true" --form file=@resources_dash.ndjson
curl -X POST "localhost:5601/api/saved_objects/_import" -H "kbn-xsrf: true" --form file=@vulns_VM_dash.ndjson
curl -X POST "localhost:5601/api/saved_objects/_import" -H "kbn-xsrf: true" --form file=@logs_dash.ndjson
