package api

import (
	"net/http"
)

// OpenAPISpec returns the OpenAPI 3.0 specification as JSON.
const OpenAPISpec = `{
  "openapi": "3.0.3",
  "info": {
    "title": "NothingDNS API",
    "description": "REST API for NothingDNS server management. Provides endpoints for zone management, cache control, cluster operations, and server monitoring.",
    "version": "1.0.0",
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
      "description": "Local development server"
    }
  ],
  "components": {
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer"
      },
      "basicAuth": {
        "type": "http",
        "scheme": "basic"
      }
    },
    "schemas": {
      "Error": {
        "type": "object",
        "properties": {
          "error": { "type": "string" }
        }
      },
      "Success": {
        "type": "object",
        "properties": {
          "status": { "type": "string", "example": "ok" },
          "message": { "type": "string" }
        }
      },
      "HealthResponse": {
        "type": "object",
        "properties": {
          "status": { "type": "string", "example": "ok" }
        }
      },
      "StatusResponse": {
        "type": "object",
        "properties": {
          "server": { "type": "string", "example": "NothingDNS" },
          "version": { "type": "string" },
          "uptime": { "type": "string" },
          "zones": { "type": "integer" },
          "cache_size": { "type": "integer" },
          "goroutines": { "type": "integer" }
        }
      },
      "Zone": {
        "type": "object",
        "properties": {
          "name": { "type": "string", "example": "example.com." },
          "records": { "type": "integer" },
          "serial": { "type": "integer" },
          "default_ttl": { "type": "integer" }
        }
      },
      "ZoneDetail": {
        "type": "object",
        "properties": {
          "name": { "type": "string" },
          "origin": { "type": "string" },
          "default_ttl": { "type": "integer" },
          "soa": { "$ref": "#/components/schemas/SOARecord" },
          "records": {
            "type": "object",
            "additionalProperties": {
              "type": "array",
              "items": { "$ref": "#/components/schemas/Record" }
            }
          }
        }
      },
      "SOARecord": {
        "type": "object",
        "properties": {
          "mname": { "type": "string" },
          "rname": { "type": "string" },
          "serial": { "type": "integer" },
          "refresh": { "type": "integer" },
          "retry": { "type": "integer" },
          "expire": { "type": "integer" },
          "minimum": { "type": "integer" }
        }
      },
      "Record": {
        "type": "object",
        "properties": {
          "name": { "type": "string", "example": "www" },
          "ttl": { "type": "integer", "example": 300 },
          "class": { "type": "string", "example": "IN" },
          "type": { "type": "string", "example": "A" },
          "rdata": { "type": "string", "example": "93.184.216.34" }
        }
      },
      "CreateZoneRequest": {
        "type": "object",
        "required": ["name"],
        "properties": {
          "name": { "type": "string", "example": "example.com." },
          "soa": { "$ref": "#/components/schemas/SOARecord" }
        }
      },
      "AddRecordRequest": {
        "type": "object",
        "required": ["name", "type", "rdata"],
        "properties": {
          "name": { "type": "string" },
          "ttl": { "type": "integer" },
          "class": { "type": "string", "default": "IN" },
          "type": { "type": "string" },
          "rdata": { "type": "string" }
        }
      },
      "CacheStats": {
        "type": "object",
        "properties": {
          "size": { "type": "integer" },
          "capacity": { "type": "integer" },
          "hits": { "type": "integer" },
          "misses": { "type": "integer" },
          "hit_rate": { "type": "number", "format": "float" }
        }
      },
      "ClusterStatus": {
        "type": "object",
        "properties": {
          "node_id": { "type": "string" },
          "state": { "type": "string" },
          "nodes": { "type": "integer" },
          "leader": { "type": "string" }
        }
      },
      "ClusterNode": {
        "type": "object",
        "properties": {
          "id": { "type": "string" },
          "address": { "type": "string" },
          "state": { "type": "string" },
          "last_seen": { "type": "string", "format": "date-time" }
        }
      },
      "DashboardStats": {
        "type": "object",
        "properties": {
          "queries_total": { "type": "integer" },
          "cache_hit_rate": { "type": "number" },
          "zones_count": { "type": "integer" },
          "uptime_seconds": { "type": "integer" }
        }
      }
    }
  },
  "security": [
    { "bearerAuth": [] },
    { "basicAuth": [] }
  ],
  "paths": {
    "/health": {
      "get": {
        "tags": ["Health"],
        "summary": "Health check",
        "description": "Returns server health status. No authentication required.",
        "security": [],
        "responses": {
          "200": {
            "description": "Server is healthy",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/HealthResponse" }
              }
            }
          }
        }
      }
    },
    "/api/v1/status": {
      "get": {
        "tags": ["Server"],
        "summary": "Server status",
        "description": "Returns server status including version, uptime, zone count, and cache size.",
        "responses": {
          "200": {
            "description": "Server status",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/StatusResponse" }
              }
            }
          }
        }
      }
    },
    "/api/v1/zones": {
      "get": {
        "tags": ["Zones"],
        "summary": "List all zones",
        "description": "Returns a list of all configured DNS zones.",
        "responses": {
          "200": {
            "description": "Zone list",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "zones": {
                      "type": "array",
                      "items": { "$ref": "#/components/schemas/Zone" }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": ["Zones"],
        "summary": "Create a new zone",
        "description": "Creates a new DNS zone with optional SOA record.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/CreateZoneRequest" }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Zone created",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Success" }
              }
            }
          },
          "400": {
            "description": "Invalid request",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Error" }
              }
            }
          },
          "409": {
            "description": "Zone already exists",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Error" }
              }
            }
          }
        }
      }
    },
    "/api/v1/zones/reload": {
      "post": {
        "tags": ["Zones"],
        "summary": "Reload zone files",
        "description": "Reloads all zone files from disk.",
        "responses": {
          "200": {
            "description": "Zones reloaded",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Success" }
              }
            }
          }
        }
      }
    },
    "/api/v1/zones/{zone}": {
      "get": {
        "tags": ["Zones"],
        "summary": "Get zone details",
        "description": "Returns detailed information about a specific zone including all records.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": { "type": "string" },
            "example": "example.com."
          }
        ],
        "responses": {
          "200": {
            "description": "Zone details",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/ZoneDetail" }
              }
            }
          },
          "404": {
            "description": "Zone not found",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Error" }
              }
            }
          }
        }
      },
      "delete": {
        "tags": ["Zones"],
        "summary": "Delete a zone",
        "description": "Deletes a DNS zone and all its records.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": { "type": "string" }
          }
        ],
        "responses": {
          "200": {
            "description": "Zone deleted",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Success" }
              }
            }
          },
          "404": {
            "description": "Zone not found"
          }
        }
      }
    },
    "/api/v1/zones/{zone}/records": {
      "get": {
        "tags": ["Records"],
        "summary": "List zone records",
        "description": "Returns all records in a zone, optionally filtered by name and type.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": { "type": "string" }
          },
          {
            "name": "name",
            "in": "query",
            "schema": { "type": "string" },
            "description": "Filter by record name"
          },
          {
            "name": "type",
            "in": "query",
            "schema": { "type": "string" },
            "description": "Filter by record type (A, AAAA, CNAME, etc.)"
          }
        ],
        "responses": {
          "200": {
            "description": "Record list",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "records": {
                      "type": "array",
                      "items": { "$ref": "#/components/schemas/Record" }
                    }
                  }
                }
              }
            }
          },
          "404": {
            "description": "Zone not found"
          }
        }
      },
      "post": {
        "tags": ["Records"],
        "summary": "Add a record",
        "description": "Adds a new DNS record to a zone.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": { "type": "string" }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/AddRecordRequest" }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Record added",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Success" }
              }
            }
          },
          "400": { "description": "Invalid request" },
          "404": { "description": "Zone not found" }
        }
      },
      "put": {
        "tags": ["Records"],
        "summary": "Update a record",
        "description": "Updates an existing DNS record in a zone.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": { "type": "string" }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/AddRecordRequest" }
            }
          }
        },
        "responses": {
          "200": { "description": "Record updated" },
          "400": { "description": "Invalid request" },
          "404": { "description": "Zone not found" }
        }
      },
      "delete": {
        "tags": ["Records"],
        "summary": "Delete a record",
        "description": "Deletes a DNS record from a zone.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": { "type": "string" }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["name", "type"],
                "properties": {
                  "name": { "type": "string" },
                  "type": { "type": "string" },
                  "rdata": { "type": "string" }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "Record deleted" },
          "404": { "description": "Zone not found" }
        }
      }
    },
    "/api/v1/zones/{zone}/export": {
      "get": {
        "tags": ["Zones"],
        "summary": "Export zone file",
        "description": "Exports the zone in BIND zone file format.",
        "parameters": [
          {
            "name": "zone",
            "in": "path",
            "required": true,
            "schema": { "type": "string" }
          }
        ],
        "responses": {
          "200": {
            "description": "Zone file content",
            "content": {
              "text/plain": {
                "schema": { "type": "string" }
              }
            }
          },
          "404": { "description": "Zone not found" }
        }
      }
    },
    "/api/v1/cache/stats": {
      "get": {
        "tags": ["Cache"],
        "summary": "Cache statistics",
        "description": "Returns cache hit/miss statistics and current size.",
        "responses": {
          "200": {
            "description": "Cache statistics",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/CacheStats" }
              }
            }
          }
        }
      }
    },
    "/api/v1/cache/flush": {
      "post": {
        "tags": ["Cache"],
        "summary": "Flush cache",
        "description": "Clears all entries from the DNS cache.",
        "responses": {
          "200": {
            "description": "Cache flushed",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Success" }
              }
            }
          }
        }
      }
    },
    "/api/v1/config/reload": {
      "post": {
        "tags": ["Config"],
        "summary": "Reload configuration",
        "description": "Reloads the server configuration from disk.",
        "responses": {
          "200": {
            "description": "Configuration reloaded",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Success" }
              }
            }
          },
          "500": {
            "description": "Reload failed",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Error" }
              }
            }
          }
        }
      }
    },
    "/api/v1/cluster/status": {
      "get": {
        "tags": ["Cluster"],
        "summary": "Cluster status",
        "description": "Returns the current cluster status including node ID and state.",
        "responses": {
          "200": {
            "description": "Cluster status",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/ClusterStatus" }
              }
            }
          }
        }
      }
    },
    "/api/v1/cluster/nodes": {
      "get": {
        "tags": ["Cluster"],
        "summary": "List cluster nodes",
        "description": "Returns all nodes in the cluster.",
        "responses": {
          "200": {
            "description": "Cluster nodes",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "nodes": {
                      "type": "array",
                      "items": { "$ref": "#/components/schemas/ClusterNode" }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/api/dashboard/stats": {
      "get": {
        "tags": ["Dashboard"],
        "summary": "Dashboard statistics",
        "description": "Returns aggregated statistics for the web dashboard.",
        "responses": {
          "200": {
            "description": "Dashboard stats",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/DashboardStats" }
              }
            }
          }
        }
      }
    }
  },
  "tags": [
    { "name": "Health", "description": "Health check endpoints" },
    { "name": "Server", "description": "Server status and information" },
    { "name": "Zones", "description": "DNS zone management" },
    { "name": "Records", "description": "DNS record management" },
    { "name": "Cache", "description": "DNS cache management" },
    { "name": "Config", "description": "Server configuration" },
    { "name": "Cluster", "description": "Cluster management" },
    { "name": "Dashboard", "description": "Web dashboard data" }
  ]
}`

// handleOpenAPISpec serves the OpenAPI JSON specification. CORS headers are
// applied by corsMiddleware — a hardcoded `Access-Control-Allow-Origin: *`
// here would bypass the configurable allowlist (VULN-034).
func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(OpenAPISpec))
}

// handleSwaggerUI serves a minimal Swagger UI page that loads the spec from /api/openapi.json.
func (s *Server) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(swaggerUIHTML))
}

const swaggerUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NothingDNS API Documentation</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>
    body { margin: 0; padding: 0; }
    #swagger-ui { max-width: 1200px; margin: 0 auto; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: '/api/openapi.json',
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis],
      layout: "BaseLayout"
    });
  </script>
</body>
</html>`
