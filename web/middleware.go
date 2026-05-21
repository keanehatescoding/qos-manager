package web

import (
	"errors"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/kakeetopius/qosm/web/routes"
)

func ErrorHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Next()

		if len(ctx.Errors) == 0 {
			return
		}

		err := ctx.Errors.Last().Err

		var serverError routes.ServerError
		if errors.As(err, &serverError) {
			ctx.JSON(serverError.StatusCode, gin.H{
				"success": false,
				"message": serverError.Error(),
			})
		}
	}
}

func ErrorHandlerHTML() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Next()

		if len(ctx.Errors) == 0 {
			return
		}

		err := ctx.Errors.Last().Err

		var serverError routes.ServerError
		if errors.As(err, &serverError) {
			ctx.HTML(serverError.StatusCode, "fail", gin.H{
				"Error": serverError.Error(),
			})
		}
	}
}

func AuthRequired() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)

		username := session.Get("username")

		if username == nil {
			ctx.Redirect(http.StatusFound, "/login")
			ctx.Abort()
			return
		}

		ctx.Next()
	}
}
