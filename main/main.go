package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

func initConfig() error {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.SetConfigType("yaml")

	return viper.ReadInConfig()
}

func getPing(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "server is healthy"})
}

func userAuthCallbackGoogle(c *gin.Context) {
	code := c.DefaultQuery("code", "")
	state := c.DefaultQuery("state", "")
	google := auth.config.Google

	if code == "" || state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code or state"})
		return
	}

	// csrf attack check
	originalState, err := c.Cookie("oauth2_state")
	if err != nil || originalState == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing state cookie"})
		return
	}

	// exchange the code for a token
	token, err := google.OAuth2Config.Exchange(c, code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to exchange token"})
		return
	}

	// use the token to fetch user information
	client := google.OAuth2Config.Client(c, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user info"})
		return
	}
	defer resp.Body.Close()

	// parse user data
	var user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse user info"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"email": user["email"], "name": user["name"]})
}

func userAuthGoogle(c *gin.Context) {
	// generate a random state string
	oauth2State, err := auth.generateStateString()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate state"})
		return
	}

	google := auth.config.Google

	// set cookie with state
	// use secure when in production as https is required
	c.SetCookie("oauth2_state", oauth2State, 3600, "", "", false, true)

	authURL := google.OAuth2Config.AuthCodeURL(oauth2State, oauth2.AccessTypeOnline)

	log.Printf("Redirecting to %s", authURL)

	c.Redirect(http.StatusFound, authURL)
}

func main() {

	readConfigErr := initConfig()
	if readConfigErr != nil {
		log.Fatalf("Error reading config file, %s", readConfigErr)
	}

	auth.loadAuthProvider()

	port := viper.GetString("server.port")
	mode := viper.GetString("server.mode")

	gin.SetMode(mode)

	router := gin.Default()
	router.GET("/ping", getPing)
	router.GET("/auth/google", userAuthGoogle)
	router.GET("/auth/google/callback", userAuthCallbackGoogle)

	router.Run("localhost:" + port)
}
