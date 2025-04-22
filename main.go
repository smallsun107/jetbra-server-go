package main

import (
	"github.com/gin-gonic/gin"
	"jetbra-server-go/internal/cert"
	"jetbra-server-go/internal/license"
	"net/http"
)

func main() {
	gin.SetMode(gin.ReleaseMode)

	r := gin.Default()
	// 静态资源挂在 /static 路径
	r.Static("/static", "./static")
	// 根路径访问 index.html
	r.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})

	// API 路由分组
	api := r.Group("/api")
	{
		api.GET("/reset", func(ctx *gin.Context) {
			if err := cert.GenerateJetCA(); err != nil {
				ctx.JSON(http.StatusOK, gin.H{"error": err.Error()})
				return
			}
			if err := cert.GeneratePowerResult(); err != nil {
				ctx.JSON(http.StatusOK, gin.H{"error": err.Error()})
				return
			}
			ctx.JSON(http.StatusOK, gin.H{"success": "gogogo"})
		})

		api.POST("/generate", func(ctx *gin.Context) {
			body, _ := ctx.GetRawData()
			ctx.JSON(http.StatusOK, gin.H{"license": license.GenerateLicense(string(body))})
		})
	}

	r.Run("0.0.0.0:2333")
}
