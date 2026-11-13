package main

import (
	"time"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine) {
	r.POST("/api/v1/go/compute", func(c *gin.Context) {
		factor := 10
		size := 20

		// GO SLEEP DOS
		time.Sleep(10 * time.Second)

		// GO CPU BOMB
		sum := 0
		for i := 0; i < factor * 100000; i++ {
			sum += i
		}

		// GO MEMORY BOMB
		buf := make([]byte, size * 1024 * 1024)

		c.JSON(200, gin.H{"sum": sum, "bytes": len(buf)})
	})
}
