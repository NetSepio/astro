package v1

import (
	"github.com/NetSepio/astro/api/v1/authenticate"
	"github.com/NetSepio/astro/api/v1/client"
	"github.com/NetSepio/astro/api/v1/server"
	caddy "github.com/NetSepio/astro/api/v1/service"
	"github.com/NetSepio/astro/api/v1/status"
	"github.com/NetSepio/astro/api/v1/agents"
	"github.com/NetSepio/astro/api/v1/operations"

	"github.com/gin-gonic/gin"
)

// ApplyRoutes Setup API EndPoints
func ApplyRoutes(r *gin.RouterGroup) {
	v1 := r.Group("/v1.0")
	{
		client.ApplyRoutes(v1)
		server.ApplyRoutes(v1)
		status.ApplyRoutes(v1)
		authenticate.ApplyRoutes(v1)
		caddy.ApplyRoutes(v1)
		agents.ApplyRoutes(v1)
		operations.ApplyRoutes(v1)
	}
}
