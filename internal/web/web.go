// Package web contains backend logic for http server.
package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Run() error {
	router := gin.Default()

	router.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "hello from qosm")
	})

	router.Run()
	return nil
}
