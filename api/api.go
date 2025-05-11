package api

import (
	v1 "github.com/NetSepio/astro/api/v1"
	"github.com/gin-gonic/gin"
)

// ApplyRoutes Setup API EndPoints
func ApplyRoutes(r *gin.Engine) {
	api := r.Group("/api")
	{
		v1.ApplyRoutes(api)
	}
}
