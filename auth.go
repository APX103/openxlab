package openxlab

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"time"

	"github.com/imroc/req/v3"
)

const (
	AuthUrl             string        = "https://sso.openxlab.org.cn/gw/uaa-be/api/v1/open"
	AuthPath            string        = "/auth"
	GetJWTPath          string        = "/getJwt"
	RefreshPath         string        = "/refreshJwt"
	RefreshBeforeExpire time.Duration = 5
)

// SSOAuth store refresh_token and jwt_token
type SSOAuth struct {
	Config            *LoginConfig `json:"config"`
	JWTToken          string       `json:"jwt_token"`
	RefreshToken      string       `json:"refresh_token"`
	Expiration        int64        `json:"expiration"`
	RefreshExpiration int64        `json:"refresh_expiration"`
}

func HmacSha1(value, keyStr string) string {
	key := []byte(keyStr)
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(value))
	res := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return res
}

func NewSSOAuth(ak string, sk string, jsk string) *SSOAuth {
	return &SSOAuth{
		Config: &LoginConfig{
			AK:           ak,
			SK:           sk,
			JWTSecretKey: jsk,
		},
	}
}

// Auth get token
func (sa *SSOAuth) Auth() (*GetTokenResponseData, error) {
	nonce, algorithm, err := getNonce(sa.Config.AK)
	if err != nil {
		logrus.Errorf("[Auth] get nonce error: %s", err)
		return nil, err
	}

	if algorithm != "HmacSHA1" {
		logrus.Errorf("[Auth] %s algorithm not support yet", algorithm)
		return nil, fmt.Errorf("[Auth] %s algorithm not support yet", algorithm)
	}

	// calculate d
	d := HmacSha1(nonce, sa.Config.SK)

	data, err := getTokenSet(sa.Config.AK, d)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (sa *SSOAuth) GetRefreshedToken() (*GetTokenResponseData, error) {
	if len(sa.Config.AK) == 0 {
		logrus.Errorf("[refresh token set] len(ak) or len(d) eq2 0")
		return nil, fmt.Errorf("len(ak) or len(d) eq2 0")
	}
	client := req.C()
	var result GetTokenResponse

	resp, err := client.R().
		SetBody(&AuthRequestBody{AK: sa.Config.AK, RefreshToken: sa.RefreshToken}).
		SetHeader("Content-Type", "application/json").
		SetHeader("accept", "application/json").
		SetSuccessResult(&result).
		Post(AuthUrl + RefreshPath)

	if err != nil {
		logrus.Errorf("[refresh token set] send req error: %s", err)
		return nil, err
	}
	if !resp.IsSuccessState() {
		logrus.Errorf("[refresh token set] bad response status: %s", resp.Status)
		return nil, err
	}

	jd := &GetTokenResponseData{}
	err = json.Unmarshal(result.Data, jd)
	if err != nil {
		logrus.Errorf("[refresh token set] unmarshal resp data error: %s", err)
		return nil, err
	}
	return jd, err
}

func (sa *SSOAuth) GetExistToken() string {
	return sa.JWTToken
}

func getNonce(ak string) (string, string, error) {
	if len(ak) == 0 {
		logrus.Errorf("[get nonce] len(ak) eq2 0")
		return "", "", fmt.Errorf("len(ak) eq2 0")
	}
	client := req.C()
	var result GetTokenResponse

	resp, err := client.R().
		SetBody(&AuthRequestBody{AK: ak}).
		SetHeader("Content-Type", "application/json").
		SetHeader("accept", "application/json").
		SetSuccessResult(&result).
		Post(AuthUrl + AuthPath)

	if err != nil {
		logrus.Errorf("[get nonce] send req error: %s", err)
		return "", "", err
	}
	if !resp.IsSuccessState() {
		logrus.Errorf("[get nonce] bad response status: %s", resp.Status)
		return "", "", err
	}

	var ad GetAuthResponseData
	err = json.Unmarshal(result.Data, &ad)
	if err != nil {
		logrus.Errorf("[get nonce] unmarshal res data error: %s", err)
		return "", "", err
	}
	logrus.Debug(string(result.Data))
	logrus.Debug(ad)

	if ad.Nonce == "" {
		logrus.Errorf("[get nonce] response error: marshal output \"\"")
		return "", "", fmt.Errorf("marshal output \"\"")
	}

	return ad.Nonce, ad.Algorithm, nil
}

func getTokenSet(ak string, d string) (*GetTokenResponseData, error) {
	if len(ak) == 0 || len(d) == 0 {
		logrus.Errorf("[get token set] len(ak) or len(d) eq2 0")
		return nil, fmt.Errorf("len(ak) or len(d) eq2 0")
	}
	client := req.C()
	var result GetTokenResponse

	resp, err := client.R().
		SetBody(&AuthRequestBody{AK: ak, D: d}).
		SetHeader("Content-Type", "application/json").
		SetHeader("accept", "application/json").
		SetSuccessResult(&result).
		Post(AuthUrl + GetJWTPath)

	if err != nil {
		logrus.Errorf("[get token set] send req error: %s", err)
		return nil, err
	}
	if !resp.IsSuccessState() {
		logrus.Errorf("[get token set] bad response status: %s", resp.Status)
		return nil, err
	}

	jd := &GetTokenResponseData{}
	err = json.Unmarshal(result.Data, jd)
	if err != nil {
		logrus.Errorf("[get token set] unmarshal res data error: %s", err)
		return nil, err
	}

	if jd.JWT == "" {
		logrus.Errorf("[get token set] response error: %s", result.Msg)
		return nil, fmt.Errorf(result.Msg)
	}

	return jd, err
}

// checkJWTExpire check if jwt token need refresh
func checkJWTExpire(RefreshExpiration int64, expireTime time.Duration) bool {
	exp := time.Now().Unix() - RefreshExpiration
	if time.Duration(exp)*time.Second < expireTime {
		return false
	}
	return true
}

func parseJWTExpire(jwtToken string) (UnixTimeSecond int64) {

	return 0
}

// GetToken is main path to get jwt token
func (sa *SSOAuth) GetToken() (string, error) {
	if sa.RefreshToken == "" || checkJWTExpire(sa.RefreshExpiration, RefreshBeforeExpire) {
		auth, err := sa.Auth()
		if err != nil {
			return "", err
		}
		sa.JWTToken = auth.JWT
		sa.RefreshToken = auth.RefreshToken
		sa.Expiration = parseJWTExpire(auth.JWT)
		sa.RefreshExpiration = parseJWTExpire(auth.RefreshExpiration)
		return auth.JWT, nil
	}

	// if RefreshToken exists, JWTToken must have value
	if checkJWTExpire(sa.Expiration, RefreshBeforeExpire) {
		token, err := sa.GetRefreshedToken()
		if err != nil {
			return "", err
		}
		sa.JWTToken = token.JWT
		sa.Expiration = parseJWTExpire(token.JWT)
		return token.JWT, nil
	}

	// get token from memory
	return sa.GetExistToken(), nil
}