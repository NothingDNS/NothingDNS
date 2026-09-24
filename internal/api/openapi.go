package api

import (
	"net/http"

	"github.com/nothingdns/nothingdns/internal/util"
)

// OpenAPISpec returns the OpenAPI 3.0 specification as JSON.
const OpenAPISpec = `{
  "openapi": "3.0.3",
  "info": {
    "title": "NothingDNS API",
    "description": "REST API for NothingDNS server management. See docs/API_REFERENCE.md for the full guide. Every operation carries x-required-role (viewer < operator < admin). DNS transports (DoH, DoWS, ODoH) and the /ws dashboard stream are described in the guide.",
    "version": "1.2.11",
    "contact": {
      "name": "ECOSTACK TECHNOLOGY OÜ"
    },
    "license": {
      "name": "MIT"
    }
  },
  "servers": [
    {
      "url": "http://localhost:8080",
      "description": "Default server.http.bind"
    }
  ],
  "components": {
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "description": "Token from /api/v1/auth/login or /api/v1/auth/bootstrap, or server.http.auth_token"
      },
      "cookieAuth": {
        "type": "apiKey",
        "in": "cookie",
        "name": "ndns_token",
        "description": "Session cookie set at login; accepted only for GET, HEAD and OPTIONS"
      }
    },
    "schemas": {
      "Error": {
        "type": "object",
        "properties": {
          "error": {
            "type": "string"
          }
        },
        "required": [
          "error"
        ]
      },
      "Success": {
        "type": "object",
        "properties": {
          "message": {
            "type": "string"
          }
        },
        "required": [
          "message"
        ],
        "description": "Plain acknowledgement."
      },
      "MessageName": {
        "type": "object",
        "properties": {
          "message": {
            "type": "string"
          },
          "name": {
            "type": "string"
          }
        }
      },
      "HealthResponse": {
        "type": "object",
        "properties": {
          "status": {
            "type": "string",
            "enum": [
              "healthy",
              "ready",
              "unhealthy",
              "alive"
            ]
          },
          "timestamp": {
            "type": "string",
            "format": "date-time"
          }
        }
      },
      "StatusResponse": {
        "type": "object",
        "properties": {
          "status": {
            "type": "string",
            "example": "running"
          },
          "timestamp": {
            "type": "string",
            "format": "date-time"
          },
          "version": {
            "type": "string"
          },
          "cache": {
            "$ref": "#/components/schemas/CacheStats",
            "description": "Operators and admins only"
          },
          "cluster": {
            "type": "object",
            "properties": {
              "enabled": {
                "type": "boolean"
              },
              "node_id": {
                "type": "string"
              },
              "node_count": {
                "type": "integer"
              },
              "alive_count": {
                "type": "integer"
              },
              "healthy": {
                "type": "boolean"
              }
            },
            "description": "Only enabled=false for viewers; details for operators and admins"
          }
        }
      },
      "Zone": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string",
            "example": "example.com."
          },
          "serial": {
            "type": "integer"
          },
          "records": {
            "type": "integer"
          }
        }
      },
      "ZoneList": {
        "type": "object",
        "properties": {
          "zones": {
            "type": "array",
            "items": {
              "$ref": "#/components/schemas/Zone"
            }
          },
          "total": {
            "type": "integer"
          },
          "truncated": {
            "type": "boolean",
            "description": "Present when more than 5000 zones exist"
          }
        }
      },
      "ZoneDetail": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string"
          },
          "serial": {
            "type": "integer"
          },
          "records": {
            "type": "integer"
          },
          "soa": {
            "$ref": "#/components/schemas/SOARecord"
          },
          "nameservers": {
            "type": "array",
            "items": {
              "type": "string"
            },
            "nullable": true
          }
        }
      },
      "SOARecord": {
        "type": "object",
        "properties": {
          "mname": {
            "type": "string"
          },
          "rname": {
            "type": "string"
          },
          "serial": {
            "type": "integer"
          },
          "refresh": {
            "type": "integer"
          },
          "retry": {
            "type": "integer"
          },
          "expire": {
            "type": "integer"
          },
          "minimum": {
            "type": "integer"
          }
        }
      },
      "Record": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string",
            "example": "www.example.com."
          },
          "type": {
            "type": "string",
            "example": "A"
          },
          "ttl": {
            "type": "integer",
            "example": 3600
          },
          "class": {
            "type": "string",
            "example": "IN"
          },
          "data": {
            "type": "string",
            "example": "192.0.2.10"
          }
        }
      },
      "RecordList": {
        "type": "object",
        "properties": {
          "records": {
            "type": "array",
            "items": {
              "$ref": "#/components/schemas/Record"
            }
          },
          "total": {
            "type": "integer"
          },
          "truncated": {
            "type": "boolean",
            "description": "Present when more than 5000 records match"
          }
        }
      },
      "CreateZoneRequest": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string",
            "example": "example.org."
          },
          "nameservers": {
            "type": "array",
            "items": {
              "type": "string"
            },
            "minItems": 1,
            "example": [
              "ns1.example.org."
            ]
          },
          "admin_email": {
            "type": "string",
            "description": "SOA RNAME in DNS form, e.g. hostmaster.example.org.",
            "example": "hostmaster.example.org."
          },
          "ttl": {
            "type": "integer",
            "description": "Default TTL, 3600 when 0 or omitted"
          }
        },
        "required": [
          "name",
          "nameservers"
        ]
      },
      "AddRecordRequest": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string",
            "description": "Owner name, relative to the zone or absolute",
            "example": "www"
          },
          "type": {
            "type": "string",
            "example": "A"
          },
          "ttl": {
            "type": "integer",
            "description": "Zone default TTL (or 3600) when 0 or omitted"
          },
          "data": {
            "type": "string",
            "example": "192.0.2.10"
          }
        },
        "required": [
          "name",
          "type",
          "data"
        ]
      },
      "UpdateRecordRequest": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string"
          },
          "type": {
            "type": "string"
          },
          "old_data": {
            "type": "string",
            "description": "Current RDATA of the record to replace (case-insensitive match)"
          },
          "data": {
            "type": "string"
          },
          "ttl": {
            "type": "integer",
            "description": "New TTL. Omitted or 0 stores TTL 0; always send it."
          }
        },
        "required": [
          "name",
          "type",
          "old_data",
          "data"
        ]
      },
      "DeleteRecordRequest": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string"
          },
          "type": {
            "type": "string"
          }
        },
        "required": [
          "name",
          "type"
        ],
        "description": "Deletes every record of this type at this owner name."
      },
      "BulkPTRRequest": {
        "type": "object",
        "properties": {
          "cidr": {
            "type": "string",
            "example": "192.0.2.0/24",
            "description": "IPv4 CIDR inside the reverse zone, at most /16"
          },
          "pattern": {
            "type": "string",
            "maxLength": 255,
            "example": "host-[A]-[B]-[C]-[D].example.com.",
            "description": "Must contain [A], [B], [C] and [D]; the result is an absolute host name"
          },
          "override": {
            "type": "boolean"
          },
          "addA": {
            "type": "boolean",
            "description": "Also add A records in the loaded forward zone that contains each generated name"
          },
          "preview": {
            "type": "boolean"
          }
        },
        "required": [
          "cidr",
          "pattern"
        ]
      },
      "BulkPTRPreview": {
        "type": "object",
        "properties": {
          "preview": {
            "type": "boolean"
          },
          "total": {
            "type": "integer"
          },
          "willAdd": {
            "type": "integer"
          },
          "willAddA": {
            "type": "integer"
          },
          "willSkip": {
            "type": "integer"
          },
          "willOverride": {
            "type": "integer"
          },
          "changes": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "ip": {
                  "type": "string"
                },
                "ptrName": {
                  "type": "string"
                },
                "aName": {
                  "type": "string"
                },
                "aZone": {
                  "type": "string",
                  "description": "Forward zone that receives the A record"
                },
                "action": {
                  "type": "string",
                  "enum": [
                    "add",
                    "override",
                    "skip"
                  ]
                },
                "ptrExist": {
                  "type": "boolean"
                },
                "aExist": {
                  "type": "boolean"
                },
                "oldPtr": {
                  "type": "string"
                },
                "oldA": {
                  "type": "string"
                },
                "revRecord": {
                  "type": "string"
                }
              }
            }
          }
        }
      },
      "BulkPTRResult": {
        "type": "object",
        "properties": {
          "added": {
            "type": "integer"
          },
          "addedA": {
            "type": "integer"
          },
          "exists": {
            "type": "integer"
          },
          "existsA": {
            "type": "integer"
          },
          "skipped": {
            "type": "integer"
          }
        }
      },
      "PTRLookup": {
        "type": "object",
        "properties": {
          "ip": {
            "type": "string"
          },
          "ptr": {
            "type": "string"
          },
          "ptrFQDN": {
            "type": "string"
          },
          "target": {
            "type": "string"
          },
          "ttl": {
            "type": "integer"
          },
          "found": {
            "type": "boolean"
          }
        }
      },
      "CacheStats": {
        "type": "object",
        "properties": {
          "size": {
            "type": "integer"
          },
          "capacity": {
            "type": "integer"
          },
          "hits": {
            "type": "integer"
          },
          "misses": {
            "type": "integer"
          },
          "hit_ratio": {
            "type": "number",
            "format": "double"
          }
        }
      },
      "CacheConfigUpdate": {
        "type": "object",
        "properties": {
          "enabled": {
            "type": "boolean",
            "description": "Only true is accepted"
          },
          "size": {
            "type": "integer",
            "minimum": 1
          },
          "default_ttl": {
            "type": "integer"
          },
          "max_ttl": {
            "type": "integer"
          },
          "min_ttl": {
            "type": "integer"
          },
          "negative_ttl": {
            "type": "integer"
          },
          "prefetch": {
            "type": "boolean"
          },
          "prefetch_threshold": {
            "type": "integer"
          },
          "serve_stale": {
            "type": "boolean"
          },
          "stale_grace_secs": {
            "type": "integer"
          }
        },
        "description": "Every field is optional; omitted fields keep their current value. Durations are seconds and must not be negative."
      },
      "RRLUpdate": {
        "type": "object",
        "properties": {
          "enabled": {
            "type": "boolean"
          },
          "rate": {
            "type": "number",
            "description": "Ignored unless > 0"
          },
          "burst": {
            "type": "integer",
            "description": "Ignored unless > 0"
          },
          "max_buckets": {
            "type": "integer",
            "minimum": 1
          }
        },
        "description": "Every field is optional; omitted fields keep their current value."
      },
      "ResolutionConfigUpdate": {
        "type": "object",
        "properties": {
          "recursive": {
            "type": "boolean"
          },
          "authoritative_only": {
            "type": "boolean"
          },
          "max_depth": {
            "type": "integer",
            "minimum": 0
          },
          "timeout": {
            "type": "string",
            "description": "Go duration string, e.g. 5s"
          },
          "edns0_buffer_size": {
            "type": "integer",
            "minimum": 0,
            "maximum": 65535
          },
          "qname_minimization": {
            "type": "boolean"
          },
          "use_0x20": {
            "type": "boolean"
          }
        },
        "description": "Every field is optional; omitted fields keep their current value. resolution.root_hints is not settable at runtime (a file path needs startup validation)."
      },
      "DNS64ConfigUpdate": {
        "type": "object",
        "properties": {
          "enabled": {
            "type": "boolean"
          }
        },
        "required": [
          "enabled"
        ],
        "description": "The DNS64 prefix is not settable at runtime; it is read when the synthesizer is built at startup."
      },
      "CookieConfigUpdate": {
        "type": "object",
        "properties": {
          "enabled": {
            "type": "boolean"
          }
        },
        "required": [
          "enabled"
        ]
      },
      "LoggingUpdate": {
        "type": "object",
        "properties": {
          "level": {
            "type": "string",
            "enum": [
              "debug",
              "info",
              "warn",
              "warning",
              "error",
              "fatal"
            ]
          }
        },
        "required": [
          "level"
        ]
      },
      "ServerConfig": {
        "type": "object",
        "properties": {
          "version": {
            "type": "string"
          },
          "listen_port": {
            "type": "integer"
          },
          "log_level": {
            "type": "string"
          },
          "dns64": {
            "type": "object",
            "properties": {
              "enabled": {
                "type": "boolean"
              },
              "prefix": {
                "type": "string"
              },
              "prefix_len": {
                "type": "integer"
              },
              "exclude_nets": {
                "type": "array",
                "items": {
                  "type": "string"
                }
              }
            }
          },
          "cookie": {
            "type": "object",
            "properties": {
              "enabled": {
                "type": "boolean"
              },
              "secret_rotation": {
                "type": "string"
              }
            }
          }
        }
      },
      "ClusterStatus": {
        "type": "object",
        "properties": {
          "node_id": {
            "type": "string"
          },
          "consensus": {
            "type": "string",
            "description": "raft or swim; empty when clustering is disabled"
          },
          "node_count": {
            "type": "integer"
          },
          "alive_count": {
            "type": "integer"
          },
          "healthy": {
            "type": "boolean"
          },
          "gossip": {
            "type": "object",
            "properties": {
              "messages_sent": {
                "type": "integer"
              },
              "messages_received": {
                "type": "integer"
              },
              "ping_sent": {
                "type": "integer"
              },
              "ping_received": {
                "type": "integer"
              }
            }
          },
          "raft": {
            "type": "object",
            "properties": {
              "state": {
                "type": "string"
              },
              "term": {
                "type": "integer"
              },
              "commit_index": {
                "type": "integer"
              },
              "applied_index": {
                "type": "integer"
              },
              "is_leader": {
                "type": "boolean"
              },
              "leader_id": {
                "type": "string"
              }
            },
            "description": "Present only in Raft mode"
          },
          "metrics": {
            "type": "object",
            "properties": {
              "queries_total": {
                "type": "integer"
              },
              "queries_per_sec": {
                "type": "number"
              },
              "cache_hits": {
                "type": "integer"
              },
              "cache_misses": {
                "type": "integer"
              },
              "cache_hit_rate": {
                "type": "number"
              },
              "latency_avg_ms": {
                "type": "number"
              },
              "latency_p99_ms": {
                "type": "number"
              }
            }
          }
        }
      },
      "ClusterNode": {
        "type": "object",
        "properties": {
          "id": {
            "type": "string"
          },
          "addr": {
            "type": "string"
          },
          "port": {
            "type": "integer"
          },
          "state": {
            "type": "string"
          },
          "role": {
            "type": "string",
            "description": "Raft role when consensus_mode is raft: leader, follower, or candidate"
          },
          "region": {
            "type": "string"
          },
          "zone": {
            "type": "string"
          },
          "weight": {
            "type": "integer"
          },
          "http_addr": {
            "type": "string"
          },
          "version": {
            "type": "integer"
          },
          "health_score": {
            "type": "integer"
          },
          "queries_per_second": {
            "type": "number"
          },
          "latency_ms": {
            "type": "number"
          },
          "cpu_percent": {
            "type": "number"
          },
          "memory_percent": {
            "type": "number"
          },
          "active_connections": {
            "type": "integer"
          }
        }
      },
      "DashboardStats": {
        "type": "object",
        "properties": {
          "uptime": {
            "type": "integer"
          },
          "queriesTotal": {
            "type": "integer"
          },
          "queriesPerSec": {
            "type": "number"
          },
          "cacheHitRate": {
            "type": "number"
          },
          "blockedQueries": {
            "type": "integer"
          },
          "activeClients": {
            "type": "integer"
          },
          "zoneCount": {
            "type": "integer"
          },
          "upstreamLatency": {
            "type": "integer"
          }
        }
      },
      "DashboardZone": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string"
          },
          "records": {
            "type": "integer",
            "description": "Number of distinct owner names"
          },
          "serial": {
            "type": "integer"
          }
        }
      },
      "QueryEvent": {
        "type": "object",
        "properties": {
          "timestamp": {
            "type": "string",
            "format": "date-time"
          },
          "clientIp": {
            "type": "string"
          },
          "countryCode": {
            "type": "string"
          },
          "domain": {
            "type": "string"
          },
          "queryType": {
            "type": "string"
          },
          "responseCode": {
            "type": "string"
          },
          "answers": {
            "type": "array",
            "items": {
              "type": "string"
            },
            "description": "Compact answer-section RDATA (e.g. \"A 93.184.216.34\")"
          },
          "duration": {
            "type": "integer"
          },
          "cached": {
            "type": "boolean"
          },
          "blocked": {
            "type": "boolean"
          },
          "protocol": {
            "type": "string"
          }
        }
      },
      "QueryLog": {
        "type": "object",
        "properties": {
          "queries": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "timestamp": {
                  "type": "string",
                  "format": "date-time"
                },
                "client_ip": {
                  "type": "string",
                  "description": "Last octet/group masked for non-admins"
                },
                "domain": {
                  "type": "string"
                },
                "query_type": {
                  "type": "string"
                },
                "response_code": {
                  "type": "string"
                },
                "answers": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  },
                  "description": "Compact answer-section RDATA"
                },
                "duration_ms": {
                  "type": "integer"
                },
                "cached": {
                  "type": "boolean"
                },
                "blocked": {
                  "type": "boolean"
                },
                "protocol": {
                  "type": "string"
                }
              }
            }
          },
          "total": {
            "type": "integer"
          },
          "offset": {
            "type": "integer"
          },
          "limit": {
            "type": "integer"
          }
        }
      },
      "TopDomains": {
        "type": "object",
        "properties": {
          "domains": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "domain": {
                  "type": "string"
                },
                "count": {
                  "type": "integer"
                }
              }
            }
          },
          "limit": {
            "type": "integer"
          }
        }
      },
      "MetricsHistory": {
        "type": "object",
        "properties": {
          "timestamps": {
            "type": "array",
            "items": {
              "type": "integer"
            }
          },
          "queries": {
            "type": "array",
            "items": {
              "type": "integer"
            }
          },
          "cache_hits": {
            "type": "array",
            "items": {
              "type": "integer"
            }
          },
          "cache_misses": {
            "type": "array",
            "items": {
              "type": "integer"
            }
          },
          "latency_ms": {
            "type": "array",
            "items": {
              "type": "integer"
            }
          },
          "count": {
            "type": "integer"
          }
        }
      },
      "LoginRequest": {
        "type": "object",
        "properties": {
          "username": {
            "type": "string"
          },
          "password": {
            "type": "string",
            "format": "password"
          }
        },
        "required": [
          "username",
          "password"
        ]
      },
      "LoginResponse": {
        "type": "object",
        "properties": {
          "token": {
            "type": "string"
          },
          "username": {
            "type": "string"
          },
          "role": {
            "type": "string"
          },
          "expires": {
            "type": "string",
            "format": "date-time"
          }
        }
      },
      "BootstrapRequest": {
        "type": "object",
        "properties": {
          "username": {
            "type": "string",
            "minLength": 2,
            "maxLength": 64
          },
          "password": {
            "type": "string",
            "format": "password",
            "minLength": 8,
            "description": "8 to 128 bytes"
          },
          "old_password": {
            "type": "string",
            "format": "password",
            "description": "Required when real users already exist (password reset)"
          }
        },
        "required": [
          "username",
          "password"
        ]
      },
      "BootstrapResponse": {
        "type": "object",
        "properties": {
          "token": {
            "type": "string"
          },
          "username": {
            "type": "string"
          },
          "role": {
            "type": "string"
          }
        }
      },
      "User": {
        "type": "object",
        "properties": {
          "username": {
            "type": "string"
          },
          "role": {
            "type": "string",
            "enum": [
              "admin",
              "operator",
              "viewer"
            ]
          },
          "created_at": {
            "type": "string",
            "format": "date-time"
          },
          "updated_at": {
            "type": "string",
            "format": "date-time"
          }
        }
      },
      "CreateUserRequest": {
        "type": "object",
        "properties": {
          "username": {
            "type": "string"
          },
          "password": {
            "type": "string",
            "format": "password",
            "description": "8 to 128 bytes"
          },
          "role": {
            "type": "string",
            "enum": [
              "admin",
              "operator",
              "viewer"
            ],
            "default": "viewer"
          }
        },
        "required": [
          "username",
          "password"
        ]
      },
      "Roles": {
        "type": "object",
        "properties": {
          "roles": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "name": {
                  "type": "string"
                },
                "description": {
                  "type": "string"
                }
              }
            }
          }
        }
      },
      "ACLRule": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string"
          },
          "networks": {
            "type": "array",
            "items": {
              "type": "string"
            },
            "description": "CIDRs (bare IPs are rejected)"
          },
          "action": {
            "type": "string",
            "enum": [
              "allow",
              "deny",
              "redirect"
            ]
          },
          "types": {
            "type": "array",
            "items": {
              "type": "string"
            },
            "description": "Query types; omit to match every type. ANY matches only QTYPE 255."
          },
          "redirect": {
            "type": "string",
            "description": "Required when action is redirect"
          }
        },
        "required": [
          "name",
          "networks",
          "action"
        ]
      },
      "RecursionPolicy": {
        "type": "object",
        "properties": {
          "allow_all": {
            "type": "boolean"
          },
          "networks": {
            "type": "array",
            "items": {
              "type": "string"
            }
          }
        }
      },
      "RecursionPolicyRequest": {
        "type": "object",
        "properties": {
          "networks": {
            "type": "array",
            "items": {
              "type": "string"
            },
            "description": "CIDRs or single IPs. [] denies recursion to every client."
          }
        },
        "required": [
          "networks"
        ]
      },
      "ACLResponse": {
        "type": "object",
        "properties": {
          "rules": {
            "type": "array",
            "items": {
              "$ref": "#/components/schemas/ACLRule"
            }
          },
          "allow_recursion": {
            "$ref": "#/components/schemas/RecursionPolicy"
          },
          "persistent": {
            "type": "boolean"
          },
          "policy_file": {
            "type": "string"
          }
        }
      },
      "ACLUpdateRequest": {
        "type": "object",
        "properties": {
          "rules": {
            "type": "array",
            "items": {
              "$ref": "#/components/schemas/ACLRule"
            }
          }
        },
        "required": [
          "rules"
        ]
      },
      "BlocklistStats": {
        "type": "object",
        "properties": {
          "enabled": {
            "type": "boolean"
          },
          "total_rules": {
            "type": "integer"
          },
          "files_count": {
            "type": "integer"
          },
          "urls_count": {
            "type": "integer"
          }
        }
      },
      "BlocklistSource": {
        "type": "object",
        "properties": {
          "id": {
            "type": "string",
            "description": "File path or URL"
          },
          "type": {
            "type": "string",
            "enum": [
              "file",
              "url"
            ]
          },
          "enabled": {
            "type": "boolean"
          },
          "domains": {
            "type": "integer"
          }
        }
      },
      "BlocklistAddRequest": {
        "type": "object",
        "properties": {
          "file": {
            "type": "string",
            "description": "Path inside blocklist.base_dir"
          },
          "url": {
            "type": "string",
            "description": "HTTPS URL"
          }
        },
        "description": "Provide exactly one of file or url (file wins if both are set)."
      },
      "RPZStats": {
        "type": "object",
        "properties": {
          "enabled": {
            "type": "boolean"
          },
          "total_rules": {
            "type": "integer"
          },
          "qname_rules": {
            "type": "integer"
          },
          "client_ip_rules": {
            "type": "integer"
          },
          "resp_ip_rules": {
            "type": "integer"
          },
          "files_count": {
            "type": "integer"
          },
          "total_matches": {
            "type": "integer"
          },
          "total_lookups": {
            "type": "integer"
          },
          "last_reload": {
            "type": "string",
            "format": "date-time"
          }
        }
      },
      "RPZRule": {
        "type": "object",
        "properties": {
          "pattern": {
            "type": "string"
          },
          "action": {
            "type": "string"
          },
          "trigger": {
            "type": "string"
          },
          "override_data": {
            "type": "string"
          },
          "policy_name": {
            "type": "string"
          },
          "priority": {
            "type": "integer"
          }
        }
      },
      "RPZRuleList": {
        "type": "object",
        "properties": {
          "rules": {
            "type": "array",
            "items": {
              "$ref": "#/components/schemas/RPZRule"
            }
          },
          "total": {
            "type": "integer"
          },
          "truncated": {
            "type": "boolean"
          }
        }
      },
      "RPZAddRuleRequest": {
        "type": "object",
        "properties": {
          "pattern": {
            "type": "string",
            "example": "ads.example.net"
          },
          "action": {
            "type": "string",
            "enum": [
              "NXDOMAIN",
              "NODATA",
              "CNAME",
              "OVERRIDE",
              "DROP",
              "PASSTHROUGH",
              "TCPONLY"
            ],
            "description": "Case-insensitive. Unknown values fall back to NXDOMAIN."
          },
          "override_data": {
            "type": "string"
          }
        },
        "required": [
          "pattern"
        ]
      },
      "Upstreams": {
        "type": "object",
        "properties": {
          "upstreams": {
            "type": "array",
            "nullable": true,
            "items": {
              "type": "object",
              "properties": {
                "address": {
                  "type": "string"
                },
                "healthy": {
                  "type": "boolean"
                },
                "queries": {
                  "type": "integer"
                },
                "failed": {
                  "type": "integer"
                },
                "failovers": {
                  "type": "integer"
                }
              }
            }
          },
          "servers": {
            "type": "array",
            "description": "Each configured upstream server with its health and last query latency",
            "items": {
              "type": "object",
              "properties": {
                "address": {
                  "type": "string",
                  "example": "1.1.1.1:53"
                },
                "healthy": {
                  "type": "boolean"
                },
                "latency_ms": {
                  "type": "number"
                }
              }
            }
          }
        }
      },
      "UpstreamUpdateRequest": {
        "type": "object",
        "properties": {
          "action": {
            "type": "string",
            "enum": [
              "add",
              "remove"
            ]
          },
          "server": {
            "type": "string",
            "example": "9.9.9.9:53"
          }
        },
        "required": [
          "action",
          "server"
        ]
      },
      "DNSSECStatus": {
        "type": "object",
        "properties": {
          "enabled": {
            "type": "boolean"
          },
          "require_dnssec": {
            "type": "boolean"
          }
        }
      },
      "DNSSECKeys": {
        "type": "object",
        "properties": {
          "zones": {
            "type": "array",
            "nullable": true,
            "items": {
              "type": "object",
              "properties": {
                "keyTag": {
                  "type": "integer"
                },
                "algorithm": {
                  "type": "integer"
                },
                "flags": {
                  "type": "integer"
                },
                "isKSK": {
                  "type": "boolean"
                },
                "isZSK": {
                  "type": "boolean"
                },
                "zone": {
                  "type": "string"
                }
              }
            }
          }
        }
      },
      "GeoIPStats": {
        "type": "object",
        "properties": {
          "enabled": {
            "type": "boolean"
          },
          "rules": {
            "type": "integer"
          },
          "mmdb_loaded": {
            "type": "boolean"
          },
          "lookups": {
            "type": "integer"
          },
          "hits": {
            "type": "integer"
          },
          "misses": {
            "type": "integer"
          }
        }
      },
      "SlaveZones": {
        "type": "object",
        "properties": {
          "slave_zones": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "zone": {
                  "type": "string"
                },
                "masters": {
                  "type": "string"
                },
                "serial": {
                  "type": "integer"
                },
                "last_transfer": {
                  "type": "string",
                  "format": "date-time"
                },
                "status": {
                  "type": "string",
                  "enum": [
                    "pending",
                    "synced"
                  ]
                },
                "records": {
                  "type": "integer"
                }
              }
            }
          }
        }
      },
      "ClusterJoinRequest": {
        "type": "object",
        "properties": {
          "seed_address": {
            "type": "string",
            "example": "10.0.0.11:7946"
          }
        },
        "required": [
          "seed_address"
        ]
      }
    }
  },
  "security": [
    {
      "bearerAuth": []
    },
    {
      "cookieAuth": []
    }
  ],
  "paths": {
    "/health": {
      "get": {
        "tags": [
          "Health"
        ],
        "summary": "Health check",
        "description": "No authentication.",
        "security": [],
        "responses": {
          "200": {
            "description": "Always healthy while the HTTP server runs",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HealthResponse"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/readyz": {
      "get": {
        "tags": [
          "Health"
        ],
        "summary": "Readiness probe",
        "description": "No authentication.",
        "security": [],
        "responses": {
          "200": {
            "description": "Ready",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HealthResponse"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "No healthy upstream",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HealthResponse"
                }
              }
            }
          }
        }
      }
    },
    "/livez": {
      "get": {
        "tags": [
          "Health"
        ],
        "summary": "Liveness probe",
        "description": "No authentication.",
        "security": [],
        "responses": {
          "200": {
            "description": "Alive",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HealthResponse"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/auth/login": {
      "post": {
        "tags": [
          "Auth"
        ],
        "summary": "Log in",
        "description": "No authentication. Returns an opaque bearer token (24 h) and sets the HttpOnly ndns_token cookie. Revokes every earlier token of the user. After a failed attempt the client IP must wait 30 s; 5 failures lock the IP (and the IP+username pair) for 5 minutes.",
        "security": [],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/LoginRequest"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Logged in",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/LoginResponse"
                }
              }
            }
          },
          "400": {
            "description": "Invalid request body",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Invalid credentials",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "Login throttled; see Retry-After",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/auth/bootstrap": {
      "post": {
        "tags": [
          "Auth"
        ],
        "summary": "Create the first admin or reset a password",
        "description": "No authentication; accepted only from 127.0.0.1 or ::1 (as seen through trusted_proxies). Replaces the auto-created default admin with the given account; when real users exist it resets the password of the named user and requires old_password.",
        "security": [],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/BootstrapRequest"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Account ready",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/BootstrapResponse"
                }
              }
            }
          },
          "400": {
            "description": "Validation error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Invalid old password",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Not from localhost",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "409": {
            "description": "User could not be created or updated",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/auth/session": {
      "get": {
        "tags": [
          "Auth"
        ],
        "summary": "Restore dashboard session after reload",
        "x-required-role": "any",
        "description": "Requires any authenticated user (Bearer or the HttpOnly ndns_token cookie on this safe GET). Returns the same token/username/role shape as login so the SPA can rebuild its in-memory bearer after a hard refresh without persisting the token in localStorage. Rejects the legacy shared auth_token.",
        "responses": {
          "200": {
            "description": "Active session",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/LoginResponse"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired session",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "405": {
            "description": "Method not allowed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/auth/logout": {
      "post": {
        "tags": [
          "Auth"
        ],
        "summary": "Log out",
        "x-required-role": "any",
        "description": "Requires any authenticated user. Revokes the bearer token and the ndns_token cookie token and clears the cookie.",
        "responses": {
          "200": {
            "description": "Logged out",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/auth/roles": {
      "get": {
        "tags": [
          "Auth"
        ],
        "summary": "List roles",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Roles",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Roles"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/auth/users": {
      "get": {
        "tags": [
          "Auth"
        ],
        "summary": "List users",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Users",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "$ref": "#/components/schemas/User"
                  }
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": [
          "Auth"
        ],
        "summary": "Create a user",
        "x-required-role": "admin",
        "description": "Requires the admin role. Persisted to server.http.users_file (default <storage.data_dir>/users.json).",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/CreateUserRequest"
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Created",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/User"
                }
              }
            }
          },
          "400": {
            "description": "Missing fields or invalid role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "409": {
            "description": "User exists or password rejected",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "delete": {
        "tags": [
          "Auth"
        ],
        "summary": "Delete a user (query form)",
        "x-required-role": "admin",
        "description": "Requires the admin role.",
        "parameters": [
          {
            "name": "username",
            "in": "query",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "User to delete"
          }
        ],
        "responses": {
          "200": {
            "description": "Deleted",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "Missing username, own account, or last admin",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "User not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/auth/users/{username}": {
      "delete": {
        "tags": [
          "Auth"
        ],
        "summary": "Delete a user",
        "x-required-role": "admin",
        "description": "Requires the admin role. Other methods on this path return 405.",
        "parameters": [
          {
            "name": "username",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "User to delete"
          }
        ],
        "responses": {
          "200": {
            "description": "Deleted",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "Own account or last admin",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "User not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/status": {
      "get": {
        "tags": [
          "Server"
        ],
        "summary": "Server status",
        "x-required-role": "any",
        "description": "Requires any authenticated user. Viewers get status, timestamp, version and cluster.enabled; operators and admins also get cache statistics and cluster details.",
        "responses": {
          "200": {
            "description": "Status",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/StatusResponse"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/server/config": {
      "get": {
        "tags": [
          "Server"
        ],
        "summary": "Server configuration summary",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Summary",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/ServerConfig"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/zones": {
      "get": {
        "tags": [
          "Zones"
        ],
        "summary": "List zones",
        "x-required-role": "operator",
        "description": "Requires the operator role. At most 5000 zones are returned.",
        "responses": {
          "200": {
            "description": "Zones",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/ZoneList"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": [
          "Zones"
        ],
        "summary": "Create a zone",
        "x-required-role": "operator",
        "description": "Requires the operator role. Creates SOA (serial 1, refresh 3600, retry 600, expire 604800, minimum 86400) and NS records. In Raft mode the write is replicated first.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/CreateZoneRequest"
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Created",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/MessageName"
                }
              }
            }
          },
          "400": {
            "description": "Missing name or nameservers",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "409": {
            "description": "Zone exists or name invalid/reserved",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "421": {
            "description": "Not the Raft leader",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Zone manager or Raft replication unavailable",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/zones/reload": {
      "post": {
        "tags": [
          "Zones"
        ],
        "summary": "Reload one zone from its file",
        "x-required-role": "admin",
        "description": "Requires the admin role.",
        "parameters": [
          {
            "name": "zone",
            "in": "query",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "Zone origin with trailing dot",
            "example": "example.com."
          }
        ],
        "responses": {
          "200": {
            "description": "Reloaded",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "Missing zone parameter",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Zone unknown, not file-backed, or file invalid",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Zone manager unavailable",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/zones/transfers": {
      "get": {
        "tags": [
          "Zones"
        ],
        "summary": "List secondary (slave) zones and transfer state",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Secondary zones",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/SlaveZones"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/zones/{zone}": {
      "get": {
        "tags": [
          "Zones"
        ],
        "summary": "Get zone details",
        "x-required-role": "operator",
        "description": "Requires the operator role. The zone name must match exactly (lowercase, trailing dot).",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "Zone origin, lowercase with trailing dot. URL-encode it if needed.",
            "example": "example.com."
          }
        ],
        "responses": {
          "200": {
            "description": "Zone",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/ZoneDetail"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Zone not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "delete": {
        "tags": [
          "Zones"
        ],
        "summary": "Delete a zone",
        "x-required-role": "operator",
        "description": "Requires the operator role. Also deletes the zone file the zone was loaded from (or written to), and its persisted copy.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "Zone origin, lowercase with trailing dot. URL-encode it if needed.",
            "example": "example.com."
          }
        ],
        "responses": {
          "200": {
            "description": "Deleted",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Zone not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "421": {
            "description": "Not the Raft leader",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/zones/{zone}/records": {
      "get": {
        "tags": [
          "Records"
        ],
        "summary": "List records",
        "x-required-role": "operator",
        "description": "Requires the operator role. At most 5000 records are returned.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "Zone origin, lowercase with trailing dot. URL-encode it if needed.",
            "example": "example.com."
          },
          {
            "name": "name",
            "in": "query",
            "required": false,
            "schema": {
              "type": "string"
            },
            "description": "Exact owner name, relative or absolute"
          }
        ],
        "responses": {
          "200": {
            "description": "Records",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/RecordList"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Zone not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": [
          "Records"
        ],
        "summary": "Add a record",
        "x-required-role": "operator",
        "description": "Requires the operator role. Class is always IN. RDATA is not validated against the type.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "Zone origin, lowercase with trailing dot. URL-encode it if needed.",
            "example": "example.com."
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/AddRecordRequest"
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Added",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "Missing fields",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Zone not found or data rejected",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "421": {
            "description": "Not the Raft leader",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "put": {
        "tags": [
          "Records"
        ],
        "summary": "Replace a record",
        "x-required-role": "operator",
        "description": "Requires the operator role. Replaces the first record matching name, type and old_data.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "Zone origin, lowercase with trailing dot. URL-encode it if needed.",
            "example": "example.com."
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/UpdateRecordRequest"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Updated",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "Missing fields",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Zone or record not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "421": {
            "description": "Not the Raft leader",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "delete": {
        "tags": [
          "Records"
        ],
        "summary": "Delete records",
        "x-required-role": "operator",
        "description": "Requires the operator role. Deletes every record of the type at the owner name.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "Zone origin, lowercase with trailing dot. URL-encode it if needed.",
            "example": "example.com."
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/DeleteRecordRequest"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Deleted",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "Missing fields",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Zone or records not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "421": {
            "description": "Not the Raft leader",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/zones/{zone}/export": {
      "get": {
        "tags": [
          "Zones"
        ],
        "summary": "Export zone file",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "Zone origin, lowercase with trailing dot. URL-encode it if needed.",
            "example": "example.com."
          }
        ],
        "responses": {
          "200": {
            "description": "BIND zone file (Content-Disposition attachment)",
            "content": {
              "text/plain": {
                "schema": {
                  "type": "string"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Zone not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/zones/{zone}/ptr-bulk": {
      "post": {
        "tags": [
          "Records"
        ],
        "summary": "Generate PTR (and A) records for an IPv4 range",
        "x-required-role": "operator",
        "description": "Requires the operator role. Zone must be an in-addr.arpa zone that contains the CIDR. Records get TTL 3600.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "Zone origin, lowercase with trailing dot. URL-encode it if needed.",
            "example": "example.com."
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/BulkPTRRequest"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Preview (preview=true) or result",
            "content": {
              "application/json": {
                "schema": {
                  "oneOf": [
                    {
                      "$ref": "#/components/schemas/BulkPTRPreview"
                    },
                    {
                      "$ref": "#/components/schemas/BulkPTRResult"
                    }
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Invalid CIDR, pattern or zone",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Zone not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/zones/{zone}/ptr6-lookup": {
      "get": {
        "tags": [
          "Records"
        ],
        "summary": "Look up the PTR for an IPv6 address",
        "x-required-role": "operator",
        "description": "Requires the operator role. Zone must be an ip6.arpa zone. Read-only.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "Zone origin, lowercase with trailing dot. URL-encode it if needed.",
            "example": "example.com."
          },
          {
            "name": "ip",
            "in": "query",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "IPv6 address",
            "example": "2001:db8::1"
          }
        ],
        "responses": {
          "200": {
            "description": "Lookup result",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/PTRLookup"
                }
              }
            }
          },
          "400": {
            "description": "Missing/invalid IP or not an ip6.arpa zone",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Zone not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/cache/stats": {
      "get": {
        "tags": [
          "Cache"
        ],
        "summary": "Cache statistics",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Statistics",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/CacheStats"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Cache disabled",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/cache/flush": {
      "post": {
        "tags": [
          "Cache"
        ],
        "summary": "Flush the cache",
        "x-required-role": "admin",
        "description": "Requires the admin role.",
        "responses": {
          "200": {
            "description": "Flushed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Cache disabled",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/config": {
      "get": {
        "tags": [
          "Config"
        ],
        "summary": "Effective configuration (secrets redacted)",
        "x-required-role": "operator",
        "description": "Requires the operator role. Go field names (PascalCase) plus Version. Reflects the loaded config file, not runtime API changes.",
        "responses": {
          "200": {
            "description": "Configuration",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "additionalProperties": true
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/config/reload": {
      "post": {
        "tags": [
          "Config"
        ],
        "summary": "Reload the configuration file",
        "x-required-role": "admin",
        "description": "Requires the admin role. Same as SIGHUP.",
        "responses": {
          "200": {
            "description": "Reloaded",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Reload failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/config/logging": {
      "put": {
        "tags": [
          "Config"
        ],
        "summary": "Change the log level at runtime",
        "x-required-role": "admin",
        "description": "Requires the admin role. Applies immediately and is persisted to <storage.data_dir>/runtime_overrides.json, which is re-applied over the config file on reload.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/LoggingUpdate"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Updated",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "Invalid log level",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/config/rrl": {
      "put": {
        "tags": [
          "Config"
        ],
        "summary": "Change the per-client DNS rate limiter at runtime",
        "x-required-role": "admin",
        "description": "Requires the admin role. Applies immediately and is persisted to <storage.data_dir>/runtime_overrides.json, which is re-applied over the config file on reload.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/RRLUpdate"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Updated",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Rate limiter unavailable",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/config/cache": {
      "put": {
        "tags": [
          "Config"
        ],
        "summary": "Change cache settings at runtime",
        "x-required-role": "admin",
        "description": "Requires the admin role. Applies immediately and is persisted to <storage.data_dir>/runtime_overrides.json, which is re-applied over the config file on reload.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/CacheConfigUpdate"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Updated",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "Invalid value or attempt to disable",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Cache disabled",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/config/resolution": {
      "put": {
        "tags": [
          "Config"
        ],
        "summary": "Change resolution settings at runtime",
        "x-required-role": "admin",
        "description": "Requires the admin role. Persisted to <storage.data_dir>/runtime_overrides.json and re-applied over the config file on reload. authoritative_only takes effect on the next query; the resolver-construction fields (recursive, max_depth, timeout, edns0_buffer_size, qname_minimization, use_0x20) take effect on the next reload or restart.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/ResolutionConfigUpdate"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Updated",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "Invalid value",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Failed to save runtime overrides",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/config/dns64": {
      "put": {
        "tags": [
          "Config"
        ],
        "summary": "Enable or disable DNS64 synthesis at runtime (RFC 6147)",
        "x-required-role": "admin",
        "description": "Requires the admin role. Applies immediately and is persisted to <storage.data_dir>/runtime_overrides.json. Enabling fails with 400 when no dns64 prefix was configured at startup.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/DNS64ConfigUpdate"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Updated",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "enabled missing, or DNS64 not configured at startup",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Failed to save runtime overrides",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/config/cookie": {
      "put": {
        "tags": [
          "Config"
        ],
        "summary": "Enable or disable DNS Cookies at runtime (RFC 7873)",
        "x-required-role": "admin",
        "description": "Requires the admin role. Creates or drops the cookie jar on the live DNS handler and is persisted to <storage.data_dir>/runtime_overrides.json.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/CookieConfigUpdate"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Updated",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "enabled missing",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Failed to save runtime overrides",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Cookie control not available",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/acl": {
      "get": {
        "tags": [
          "ACL"
        ],
        "summary": "Get ACL rules and the recursion allow list",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Access policy",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/ACLResponse"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "put": {
        "tags": [
          "ACL"
        ],
        "summary": "Replace ACL rules",
        "x-required-role": "admin",
        "description": "Requires the admin role. Rules are checked in order, first match wins; once any rule exists, clients matching none are refused. Saved with the recursion list to <storage.data_dir>/access_policy.json, which then overrides the config file.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/ACLUpdateRequest"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Updated",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "Invalid rule",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Could not save the policy file",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/acl/recursion": {
      "get": {
        "tags": [
          "ACL"
        ],
        "summary": "Get the recursion allow list",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Recursion policy",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/RecursionPolicy"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "put": {
        "tags": [
          "ACL"
        ],
        "summary": "Replace the recursion allow list",
        "x-required-role": "admin",
        "description": "Requires the admin role. Clients outside the list still get answers from local zones; other names get REFUSED with EDE 18. Saved to <storage.data_dir>/access_policy.json.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/RecursionPolicyRequest"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "New policy",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/RecursionPolicy"
                }
              }
            }
          },
          "400": {
            "description": "networks missing or invalid",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Could not save the policy file",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Recursion policy unavailable",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/blocklists": {
      "get": {
        "tags": [
          "Blocklists"
        ],
        "summary": "Blocklist statistics",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Statistics",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/BlocklistStats"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": [
          "Blocklists"
        ],
        "summary": "Add a blocklist source",
        "x-required-role": "admin",
        "description": "Requires the admin role. Runtime only; not written to the config file.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/BlocklistAddRequest"
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Added",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "Missing source, base_dir not set, or load failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Blocklist disabled",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/blocklists/sources": {
      "get": {
        "tags": [
          "Blocklists"
        ],
        "summary": "List blocklist sources",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Sources",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "$ref": "#/components/schemas/BlocklistSource"
                  },
                  "nullable": true
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Blocklist disabled",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/blocklists/toggle": {
      "post": {
        "tags": [
          "Blocklists"
        ],
        "summary": "Toggle blocklist filtering on or off",
        "x-required-role": "admin",
        "description": "Requires the admin role.",
        "responses": {
          "200": {
            "description": "New state",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Blocklist disabled",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/blocklists/{source}": {
      "delete": {
        "tags": [
          "Blocklists"
        ],
        "summary": "Remove a blocklist source",
        "x-required-role": "admin",
        "description": "Requires the admin role.",
        "parameters": [
          {
            "name": "source",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "Source id (file path or URL), URL-encoded"
          }
        ],
        "responses": {
          "200": {
            "description": "Removed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "Unknown source",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Blocklist disabled",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/blocklists/{source}/toggle": {
      "post": {
        "tags": [
          "Blocklists"
        ],
        "summary": "Toggle one source",
        "x-required-role": "admin",
        "description": "Requires the admin role.",
        "parameters": [
          {
            "name": "source",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "Source id (file path or URL), URL-encoded"
          }
        ],
        "responses": {
          "200": {
            "description": "New state",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Source not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Blocklist disabled",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/rpz": {
      "get": {
        "tags": [
          "RPZ"
        ],
        "summary": "RPZ statistics",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Statistics",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/RPZStats"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/rpz/rules": {
      "get": {
        "tags": [
          "RPZ"
        ],
        "summary": "List QNAME rules",
        "x-required-role": "operator",
        "description": "Requires the operator role. At most 5000 rules are returned.",
        "responses": {
          "200": {
            "description": "Rules",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/RPZRuleList"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": [
          "RPZ"
        ],
        "summary": "Add a QNAME rule",
        "x-required-role": "admin",
        "description": "Requires the admin role. In memory only; lost on reload or restart.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/RPZAddRuleRequest"
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Added",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "pattern missing",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "RPZ disabled",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "delete": {
        "tags": [
          "RPZ"
        ],
        "summary": "Delete a QNAME rule",
        "x-required-role": "admin",
        "description": "Requires the admin role.",
        "parameters": [
          {
            "name": "pattern",
            "in": "query",
            "required": true,
            "schema": {
              "type": "string"
            },
            "description": "Rule pattern"
          }
        ],
        "responses": {
          "200": {
            "description": "Removed (also when no rule matched)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "pattern missing",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "RPZ disabled",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/rpz/toggle": {
      "post": {
        "tags": [
          "RPZ"
        ],
        "summary": "Toggle RPZ filtering on or off",
        "x-required-role": "admin",
        "description": "Requires the admin role.",
        "responses": {
          "200": {
            "description": "New state",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "RPZ disabled",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/dnssec/status": {
      "get": {
        "tags": [
          "DNSSEC"
        ],
        "summary": "DNSSEC validation status",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Status",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/DNSSECStatus"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/dnssec/keys": {
      "get": {
        "tags": [
          "DNSSEC"
        ],
        "summary": "List DNSSEC signing keys (public metadata)",
        "x-required-role": "admin",
        "description": "Requires the admin role.",
        "responses": {
          "200": {
            "description": "Keys",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/DNSSECKeys"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/upstreams": {
      "get": {
        "tags": [
          "Upstreams"
        ],
        "summary": "Upstream health and counters",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Upstreams",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Upstreams"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "put": {
        "tags": [
          "Upstreams"
        ],
        "summary": "Add or remove one upstream server",
        "x-required-role": "admin",
        "description": "Requires the admin role. Private and internal addresses are rejected; host names are resolved and pinned to the first public IP. Runtime only.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/UpstreamUpdateRequest"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Changed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "Invalid action or address",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Server not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "409": {
            "description": "Server already present",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Upstream client not configured",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/geoip/stats": {
      "get": {
        "tags": [
          "GeoIP"
        ],
        "summary": "GeoDNS statistics",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Statistics",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/GeoIPStats"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/cluster/status": {
      "get": {
        "tags": [
          "Cluster"
        ],
        "summary": "Cluster status",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Status (zero values when clustering is off)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/ClusterStatus"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/cluster/nodes": {
      "get": {
        "tags": [
          "Cluster"
        ],
        "summary": "Cluster nodes",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Nodes",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "nodes": {
                      "type": "array",
                      "items": {
                        "$ref": "#/components/schemas/ClusterNode"
                      }
                    }
                  }
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/cluster/join": {
      "post": {
        "tags": [
          "Cluster"
        ],
        "summary": "Join a cluster through a seed node",
        "x-required-role": "admin",
        "description": "Requires the admin role. Gossip (SWIM) mode only.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/ClusterJoinRequest"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Joined",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "400": {
            "description": "Invalid seed or join failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Clustering disabled",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/cluster/leave": {
      "delete": {
        "tags": [
          "Cluster"
        ],
        "summary": "Drain and leave the cluster",
        "x-required-role": "admin",
        "description": "Requires the admin role.",
        "responses": {
          "200": {
            "description": "Left",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Success"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Drain or leave failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Clustering disabled",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/dashboard/stats": {
      "get": {
        "tags": [
          "Dashboard"
        ],
        "summary": "Dashboard counters",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Counters",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/DashboardStats"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/dashboard/queries": {
      "get": {
        "tags": [
          "Dashboard"
        ],
        "summary": "Last 100 query events",
        "x-required-role": "operator",
        "description": "Requires the operator role. Client IPs are not masked.",
        "responses": {
          "200": {
            "description": "Events",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "$ref": "#/components/schemas/QueryEvent"
                  }
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Dashboard unavailable",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/dashboard/zones": {
      "get": {
        "tags": [
          "Dashboard"
        ],
        "summary": "Zone summary for the dashboard",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "Zones",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "$ref": "#/components/schemas/DashboardZone"
                  }
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/queries": {
      "get": {
        "tags": [
          "Metrics"
        ],
        "summary": "Query log",
        "x-required-role": "operator",
        "description": "Requires the operator role. Client IPs are masked unless the caller is an admin.",
        "parameters": [
          {
            "name": "offset",
            "in": "query",
            "required": false,
            "schema": {
              "type": "integer"
            },
            "description": "Start index (default 0)"
          },
          {
            "name": "limit",
            "in": "query",
            "required": false,
            "schema": {
              "type": "integer"
            },
            "description": "1-500 (default 100)"
          },
          {
            "name": "q",
            "in": "query",
            "required": false,
            "schema": {
              "type": "string"
            },
            "description": "Case-insensitive domain substring filter"
          }
        ],
        "responses": {
          "200": {
            "description": "Query log page",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/QueryLog"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Dashboard unavailable",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/topdomains": {
      "get": {
        "tags": [
          "Metrics"
        ],
        "summary": "Most-queried domains",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "parameters": [
          {
            "name": "limit",
            "in": "query",
            "required": false,
            "schema": {
              "type": "integer"
            },
            "description": "1-100 (default 10)"
          }
        ],
        "responses": {
          "200": {
            "description": "Top domains",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/TopDomains"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Dashboard unavailable",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/metrics/history": {
      "get": {
        "tags": [
          "Metrics"
        ],
        "summary": "Metrics history ring buffer",
        "x-required-role": "operator",
        "description": "Requires the operator role.",
        "responses": {
          "200": {
            "description": "History, newest sample first",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/MetricsHistory"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "403": {
            "description": "Insufficient role",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "503": {
            "description": "Metrics unavailable",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/csp-report": {
      "post": {
        "tags": [
          "Security"
        ],
        "summary": "Content-Security-Policy violation report sink",
        "description": "No authentication. Accepts the browser envelope {\"csp-report\": {...}} and logs it.",
        "security": [],
        "requestBody": {
          "required": false,
          "content": {
            "application/json": {
              "schema": {
                "type": "object"
              }
            }
          }
        },
        "responses": {
          "204": {
            "description": "Accepted (also for malformed bodies)"
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/openapi.json": {
      "get": {
        "tags": [
          "Docs"
        ],
        "summary": "This OpenAPI document",
        "x-required-role": "any",
        "description": "Requires any authenticated user.",
        "responses": {
          "200": {
            "description": "OpenAPI 3.0 JSON",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/docs/app.js": {
      "get": {
        "tags": [
          "Docs"
        ],
        "summary": "API explorer script",
        "x-required-role": "any",
        "description": "Requires any authenticated user.",
        "responses": {
          "200": {
            "description": "JavaScript",
            "content": {
              "text/javascript": {
                "schema": {
                  "type": "string"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/api/docs": {
      "get": {
        "tags": [
          "Docs"
        ],
        "summary": "API explorer page",
        "x-required-role": "any",
        "description": "Requires any authenticated user. Self-contained page (no CDN) that renders this specification; its script is /api/docs/app.js.",
        "responses": {
          "200": {
            "description": "HTML page",
            "content": {
              "text/html": {
                "schema": {
                  "type": "string"
                }
              }
            }
          },
          "401": {
            "description": "Missing, invalid or expired token",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "API rate limit exceeded (per client IP; see server.http.api_rate_limit)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    }
  },
  "tags": [
    {
      "name": "Health",
      "description": "Health and Kubernetes probes"
    },
    {
      "name": "Auth",
      "description": "Login, bootstrap and user management"
    },
    {
      "name": "Server",
      "description": "Server status and information"
    },
    {
      "name": "Zones",
      "description": "DNS zone management"
    },
    {
      "name": "Records",
      "description": "DNS record management"
    },
    {
      "name": "Cache",
      "description": "DNS cache"
    },
    {
      "name": "Config",
      "description": "Runtime configuration"
    },
    {
      "name": "ACL",
      "description": "Access control and recursion policy"
    },
    {
      "name": "Blocklists",
      "description": "Domain blocklists"
    },
    {
      "name": "RPZ",
      "description": "Response Policy Zones"
    },
    {
      "name": "DNSSEC",
      "description": "DNSSEC"
    },
    {
      "name": "Upstreams",
      "description": "Upstream forwarding"
    },
    {
      "name": "GeoIP",
      "description": "GeoDNS"
    },
    {
      "name": "Cluster",
      "description": "Cluster management"
    },
    {
      "name": "Dashboard",
      "description": "Web dashboard data"
    },
    {
      "name": "Metrics",
      "description": "Query log and metrics"
    },
    {
      "name": "Security",
      "description": "Browser security reporting"
    },
    {
      "name": "Docs",
      "description": "API documentation"
    }
  ]
}`

// handleOpenAPISpec serves the OpenAPI JSON specification. CORS headers are
// applied by corsMiddleware — a hardcoded `Access-Control-Allow-Origin: *`
// here would bypass the configurable allowlist (VULN-034).
func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	writeRawResponse(w, "application/json", []byte(OpenAPISpec))
}

// handleSwaggerUI serves the API explorer page. It renders
// /api/openapi.json with a small same-origin script instead of loading
// Swagger UI from a CDN: the server's Content-Security-Policy
// (script-src 'self') blocks third-party scripts, and loading them into the
// authenticated dashboard origin would be a supply-chain risk (VULN-012).
func (s *Server) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	writeRawResponse(w, "text/html; charset=utf-8", []byte(apiExplorerHTML))
}

// handleAPIExplorerScript serves the explorer's script.
func (s *Server) handleAPIExplorerScript(w http.ResponseWriter, r *http.Request) {
	writeRawResponse(w, "text/javascript; charset=utf-8", []byte(apiExplorerJS))
}

func writeRawResponse(w http.ResponseWriter, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	if _, err := w.Write(body); err != nil {
		util.Warnf("api: failed to write response: %v", err)
	}
}

const apiExplorerHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NothingDNS API</title>
<style>
:root { color-scheme: light dark; --fg:#1f2328; --muted:#59636e; --bg:#fff; --panel:#f6f8fa; --border:#d1d9e0;
  --get:#0969da; --post:#1a7f37; --put:#9a6700; --delete:#cf222e; --patch:#8250df; }
@media (prefers-color-scheme: dark) { :root { --fg:#e6edf3; --muted:#9198a1; --bg:#0d1117; --panel:#151b23; --border:#3d444d;
  --get:#4493f8; --post:#3fb950; --put:#d29922; --delete:#f85149; --patch:#ab7df8; } }
* { box-sizing: border-box; }
body { margin: 0; font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--fg); background: var(--bg); }
header { padding: 20px 24px 12px; border-bottom: 1px solid var(--border); }
h1 { margin: 0 0 4px; font-size: 22px; }
.sub { color: var(--muted); margin: 0; }
main { max-width: 1100px; margin: 0 auto; padding: 16px 24px 48px; }
input[type=search] { width: 100%; padding: 8px 10px; font: inherit; color: inherit; background: var(--panel); border: 1px solid var(--border); border-radius: 6px; }
h2 { font-size: 16px; margin: 28px 0 8px; }
details.op { border: 1px solid var(--border); border-radius: 6px; margin: 6px 0; background: var(--panel); }
details.op > summary { cursor: pointer; padding: 8px 12px; display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; list-style: none; }
.method { font: 600 12px ui-monospace, monospace; min-width: 56px; text-align: center; padding: 2px 6px; border-radius: 4px; color: #fff; }
.path { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
.summary { color: var(--muted); }
.role { margin-left: auto; font-size: 12px; border: 1px solid var(--border); border-radius: 999px; padding: 0 8px; }
.body { padding: 4px 12px 12px; border-top: 1px solid var(--border); }
table { border-collapse: collapse; width: 100%; margin: 6px 0; }
th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
pre { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 8px; overflow: auto; font-size: 12px; }
.msg { padding: 16px; border: 1px solid var(--border); border-radius: 6px; background: var(--panel); }
a { color: var(--get); }
</style>
</head>
<body>
<header>
  <h1 id="title">NothingDNS API</h1>
  <p class="sub" id="subtitle">Loading <a href="/api/openapi.json">/api/openapi.json</a>…</p>
</header>
<main>
  <input type="search" id="filter" placeholder="Filter by path, summary or tag" aria-label="Filter operations">
  <div id="content"></div>
</main>
<script src="/api/docs/app.js"></script>
</body>
</html>`

const apiExplorerJS = `(function () {
  'use strict';
  var colors = { get: 'var(--get)', post: 'var(--post)', put: 'var(--put)', delete: 'var(--delete)', patch: 'var(--patch)' };
  var content = document.getElementById('content');
  var spec = null;

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'text') node.textContent = attrs[k]; else node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }

  function resolve(schema, depth) {
    if (!schema || depth > 6) return schema;
    if (schema.$ref) {
      var name = schema.$ref.split('/').pop();
      var target = (spec.components && spec.components.schemas || {})[name];
      return target ? resolve(target, depth + 1) : schema;
    }
    var out = {};
    Object.keys(schema).forEach(function (k) {
      var v = schema[k];
      if (k === 'properties' && v) {
        out.properties = {};
        Object.keys(v).forEach(function (p) { out.properties[p] = resolve(v[p], depth + 1); });
      } else if (k === 'items') {
        out.items = resolve(v, depth + 1);
      } else {
        out[k] = v;
      }
    });
    return out;
  }

  function schemaBlock(label, media) {
    var json = media && media['application/json'];
    if (!json || !json.schema) return null;
    return el('div', {}, [
      el('strong', { text: label }),
      el('pre', { text: JSON.stringify(resolve(json.schema, 0), null, 2) })
    ]);
  }

  function operation(path, method, op) {
    var summary = el('summary', {}, [
      el('span', { 'class': 'method', style: 'background:' + (colors[method] || 'var(--muted)'), text: method.toUpperCase() }),
      el('span', { 'class': 'path', text: path }),
      el('span', { 'class': 'summary', text: op.summary || '' }),
      op['x-required-role'] ? el('span', { 'class': 'role', text: 'role: ' + op['x-required-role'] }) : null
    ]);
    var body = el('div', { 'class': 'body' });
    if (op.description) body.appendChild(el('p', { text: op.description }));
    if (op.parameters && op.parameters.length) {
      var rows = op.parameters.map(function (p) {
        return el('tr', {}, [
          el('td', {}, [el('code', { text: p.name })]),
          el('td', { text: p['in'] || '' }),
          el('td', { text: p.required ? 'yes' : 'no' }),
          el('td', { text: p.description || '' })
        ]);
      });
      body.appendChild(el('table', {}, [
        el('thead', {}, [el('tr', {}, ['Parameter', 'In', 'Required', 'Description'].map(function (h) { return el('th', { text: h }); }))]),
        el('tbody', {}, rows)
      ]));
    }
    if (op.requestBody) body.appendChild(schemaBlock('Request body', op.requestBody.content));
    Object.keys(op.responses || {}).forEach(function (code) {
      var r = op.responses[code];
      body.appendChild(el('p', {}, [el('strong', { text: code + ' ' }), document.createTextNode(r.description || '')]));
      var block = schemaBlock('Schema', r.content);
      if (block) body.appendChild(block);
    });
    var details = el('details', { 'class': 'op' }, [summary, body]);
    details.dataset.search = (method + ' ' + path + ' ' + (op.summary || '') + ' ' + (op.tags || []).join(' ')).toLowerCase();
    return details;
  }

  function render() {
    content.textContent = '';
    var groups = {};
    Object.keys(spec.paths || {}).sort().forEach(function (path) {
      Object.keys(spec.paths[path]).forEach(function (method) {
        var op = spec.paths[path][method];
        if (!op || typeof op !== 'object' || !op.responses && !op.summary) return;
        var tag = (op.tags && op.tags[0]) || 'Other';
        (groups[tag] = groups[tag] || []).push(operation(path, method, op));
      });
    });
    Object.keys(groups).sort().forEach(function (tag) {
      var section = el('section', {}, [el('h2', { text: tag })]);
      groups[tag].forEach(function (d) { section.appendChild(d); });
      content.appendChild(section);
    });
    applyFilter();
  }

  function applyFilter() {
    var q = document.getElementById('filter').value.trim().toLowerCase();
    Array.prototype.forEach.call(content.querySelectorAll('section'), function (section) {
      var visible = 0;
      Array.prototype.forEach.call(section.querySelectorAll('details.op'), function (d) {
        var show = !q || d.dataset.search.indexOf(q) !== -1;
        d.style.display = show ? '' : 'none';
        if (show) visible++;
      });
      section.style.display = visible ? '' : 'none';
    });
  }

  document.getElementById('filter').addEventListener('input', applyFilter);

  fetch('/api/openapi.json', { credentials: 'same-origin' })
    .then(function (res) {
      if (res.status === 401) throw new Error('Sign in to the dashboard first, then reload this page.');
      if (!res.ok) throw new Error('Could not load /api/openapi.json (HTTP ' + res.status + ').');
      return res.json();
    })
    .then(function (data) {
      spec = data;
      document.getElementById('title').textContent = (spec.info && spec.info.title) || 'API';
      document.getElementById('subtitle').textContent =
        'Version ' + ((spec.info && spec.info.version) || '?') + ' · Send "Authorization: Bearer <token>" for scripted access · raw spec: /api/openapi.json';
      render();
    })
    .catch(function (err) {
      document.getElementById('subtitle').textContent = '';
      content.appendChild(el('div', { 'class': 'msg', role: 'alert', text: err.message }));
    });
})();
`
