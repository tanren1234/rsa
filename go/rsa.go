package main

import (
	"encoding/base64"
	"github.com/farmerx/gorsa"
	"github.com/gin-gonic/gin"
	"net/http"
)
var msg struct {
	data    string `json:"user"`
	msg string
	code  int
}
func main() {
	router := gin.Default()
	router.LoadHTMLGlob("templates/*")
	//router.LoadHTMLFiles("templates/template1.html", "templates/template2.html")
	router.GET("/index", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"title": "Main website",
		})
	})
	v1 := router.Group("/api")
	{
		v1.POST("/encryption", encryption)
		v1.POST("/decryption", decryption)
	}
	router.Run(":8085")
}

func decryption(context *gin.Context) {
	prikey := context.PostForm("prikey")
	textencry := context.PostForm("textencry")

	msg.data = ""
	msg.msg = "success"
	msg.code = 200
	if err := gorsa.RSA.SetPrivateKey(prikey); err != nil {
		msg.msg = err.Error()
		msg.code = 500
		context.JSON(http.StatusOK,gin.H{
			"msg":msg.msg,
			"data":msg.data,
			"code":msg.code,
		})
		return
	}
	sEnc,_:=base64.StdEncoding.DecodeString(textencry)

	pridecrypt, err := gorsa.RSA.PriKeyDECRYPT(sEnc)
	if err != nil {
		msg.msg=err.Error()
		msg.code=500
		context.JSON(http.StatusOK,gin.H{
			"msg":msg.msg,
			"data":msg.data,
			"code":msg.code,
		})
		return
	}

	msg.data = string(pridecrypt)
	context.JSON(http.StatusOK,gin.H{
		"msg":msg.msg,
		"data":msg.data,
		"code":msg.code,
	})
}

func encryption(context *gin.Context) {
	pubkey := context.PostForm("pubkey")
	textorigin := context.PostForm("textorigin")

	msg.data = ""
	msg.msg = "success"
	msg.code = 200
	if err := gorsa.RSA.SetPublicKey(pubkey); err != nil {
		msg.msg = err.Error()
		context.JSON(http.StatusOK,gin.H{
			"msg":msg.msg,
			"data":msg.data,
			"code":msg.code,
		})
		return
	}
	pubenctypt, err := gorsa.RSA.PubKeyENCTYPT([]byte(textorigin))
	if err != nil {
		msg.msg = err.Error()
		context.JSON(http.StatusOK,gin.H{
			"msg":msg.msg,
			"data":msg.data,
			"code":msg.code,
		})
		return
	}
	sEnc:=base64.StdEncoding.EncodeToString(pubenctypt)
	msg.data = sEnc
	context.JSON(http.StatusOK,gin.H{
		"msg":msg.msg,
		"data":msg.data,
		"code":msg.code,
	})
}
