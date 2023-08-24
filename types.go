package openxlab

import (
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
)

type LoginConfig struct {
	AK           string `json:"ak"`
	SK           string `json:"sk"`
	JWTSecretKey string `json:"jwt_secret_key"`
}

type GetTokenResponse struct {
	TraceId string          `json:"traceId,omitempty"`
	MsgCode string          `json:"msgCode,omitempty"`
	Msg     string          `json:"msg,omitempty"`
	Data    json.RawMessage `json:"data"`
	Total   json.RawMessage `json:"total,omitempty"`
}

type GetTokenResponseData struct {
	RefreshToken      string `json:"refresh_token"`
	SSOUID            string `json:"sso_uid"`
	JWT               string `json:"jwt"`
	RefreshExpiration string `json:"refresh_expiration"`
	Expiration        string `json:"expiration"`
}

type GetAuthResponseData struct {
	Nonce     string `json:"nonce"`
	Algorithm string `json:"algorithm"`
}

type AuthRequestBody struct {
	AK           string `json:"ak,omitempty"`
	D            string `json:"d,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type SSOJWTClaim struct {
	EXP int64  `json:"exp"`
	AK  string `json:"ak"`
	jwt.RegisteredClaims
}
