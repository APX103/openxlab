package main

import (
	"bytes"
	"fmt"
	"github.com/APX103/openxlab"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

type Formatter struct{}

func (m *Formatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	timestamp := entry.Time.Format("2006-01-02 15:04:05")
	var newLog string

	if entry.HasCaller() {
		fName := filepath.Base(entry.Caller.File)
		newLog = fmt.Sprintf("[logrus] [%s] [%s] [%s:%d %s] %s\n",
			timestamp, entry.Level, fName, entry.Caller.Line, entry.Caller.Function, entry.Message)
	} else {
		newLog = fmt.Sprintf("[logrus] [%s] [%s] %s\n", timestamp, entry.Level, entry.Message)
	}

	b.WriteString(newLog)
	return b.Bytes(), nil
}

var config *SSOConfig
var sa *openxlab.SSOAuth

func init() {
	lvl, ok := os.LookupEnv("LOG_LEVEL")
	if !ok {
		lvl = "info"
	}
	ll, err := logrus.ParseLevel(lvl)
	if err != nil {
		ll = logrus.InfoLevel
	}
	logrus.SetLevel(ll)
	logrus.SetReportCaller(true)
	logrus.SetFormatter(&Formatter{})

	// inject config
	getConfig(config)
	sa = openxlab.NewSSOAuth(config.AK, config.SK, config.JSK)
}

// config

type SSOConfig struct {
	AK  string `yaml:"ak"`
	SK  string `yaml:"sk"`
	JSK string `yaml:"jwt_secret_token"`
}

func getConfig(config *SSOConfig) {
	logrus.Debug(" Getting config ")
	yamlFile, err := os.ReadFile("config.yaml")
	if err != nil {
		logrus.Error(err)
		panic("Can not get config file")
	}

	err = yaml.Unmarshal(yamlFile, config)
	if err != nil {
		panic(err)
	}
	logrus.Debug(" Got config ")
}

// router

func Ping(c *gin.Context) {
	logrus.Info("a sample app log")
	c.JSON(200, gin.H{
		"message": "pong",
	})
}

func GetToken(c *gin.Context) {
	logrus.Info("getting token")
	c.JSON(200, gin.H{
		"token": sa.GetToken(),
	})
}

func main() {
	r := gin.Default()
	r.GET("/", GetToken)
	r.GET("/ping", Ping)
	if err := r.Run(":10086"); err != nil {
		logrus.WithError(err).Errorf("init fail")
	}
}
