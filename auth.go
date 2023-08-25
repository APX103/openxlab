package openxlab

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"

	"github.com/imroc/req/v3"
)

const (
	AuthUrl             string        = "https://sso.openxlab.org.cn/gw/uaa-be/api/v1/open"
	AuthPath            string        = "/auth"
	GetJWTPath          string        = "/getJwt"
	RefreshPath         string        = "/refreshJwt"
	RefreshBeforeExpire time.Duration = 5 * time.Minute
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

// isJWTExpired check if jwt has expired with an offset
func isJWTExpired(expiration int64, offset time.Duration) bool {
	expireIn := expiration - time.Now().Unix()
	return time.Duration(expireIn)*time.Second < offset
}

func (sa *SSOAuth) parseJWTExpire(jwtToken string) (UnixTimeSecond int64, err error) {
	hmacSampleSecret := []byte(sa.Config.JWTSecretKey)

	token, err := jwt.ParseWithClaims(jwtToken, &SSOJWTClaim{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return hmacSampleSecret, nil
	})

	// need valid : token.Valid
	if claims, ok := token.Claims.(*SSOJWTClaim); ok {
		logrus.Info(claims.EXP, claims.AK)
		return claims.EXP, nil
	} else {
		logrus.Errorf("parse expire err")
		return 0, err
	}
}

// GetToken is main path to get jwt token
func (sa *SSOAuth) GetToken() (string, error) {
	if sa.RefreshToken == "" || isJWTExpired(sa.RefreshExpiration, RefreshBeforeExpire) {
		auth, err := sa.Auth()
		if err != nil {
			return "", err
		}
		sa.JWTToken = auth.JWT
		sa.RefreshToken = auth.RefreshToken
		sa.Expiration, _ = sa.parseJWTExpire(sa.JWTToken[7:])
		sa.RefreshExpiration, _ = sa.parseJWTExpire(sa.RefreshToken[7:])
		return auth.JWT, nil
	}

	// if RefreshToken exists, JWTToken must have value
	if isJWTExpired(sa.Expiration, RefreshBeforeExpire) {
		token, err := sa.GetRefreshedToken()
		if err != nil {
			return "", err
		}
		sa.JWTToken = token.JWT
		sa.Expiration, _ = sa.parseJWTExpire(token.JWT[7:])
		return token.JWT, nil
	}

	// get token from memory
	return sa.GetExistToken(), nil
}
