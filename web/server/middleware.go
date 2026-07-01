package server

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func ErrorHandlerJSON() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Next()

		if len(ctx.Errors) == 0 {
			return
		}

		err := ctx.Errors.Last().Err

		var serverError ServerError
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

		var serverError ServerError
		if errors.As(err, &serverError) {
			ctx.HTML(serverError.StatusCode, "fail", gin.H{
				"Error": serverError.Error(),
			})
		}
	}
}

func ErrorHandlerToast(app *Server) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Next()

		if len(ctx.Errors) == 0 {
			return
		}

		err := ctx.Errors.Last().Err

		app.Logger.Error("server_error", "Error", err.Error())

		ctx.HTML(http.StatusOK, "toast_error", gin.H{
			"Message": "Error: " + err.Error(),
		})
	}
}

func AuthRequired(app *Server) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)

		username := session.Get("username")

		if username == nil {
			if ctx.GetHeader("HX-Request") == "true" {
				ctx.Header("HX-Redirect", "/login")
				ctx.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			ctx.Redirect(http.StatusFound, "/login")
			ctx.Abort()
			return
		}

		ctx.Next()
	}
}

func (app *Server) SetUpSessionMiddleWare(router *gin.Engine, authKey string, encKey string) error {
	derivedAuthKey, err := genKey(authKey, 64)
	if err != nil {
		return err
	}
	derivedEncKey, err := genKey(encKey, 32)
	if err != nil {
		return err
	}
	store := cookie.NewStore(derivedAuthKey, derivedEncKey)

	router.Use(sessions.Sessions("qosm-session", store))

	return nil
}

func genKey(secret string, keyLen int) ([]byte, error) {
	hash := sha256.New

	return hkdf.Key(hash, []byte(secret), nil, "", keyLen)
}
