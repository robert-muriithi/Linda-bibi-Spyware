package utils

import (
	"github.com/dgrijalva/jwt-go"
	request2 "slam-engine/src/models/request"
	"time"
)

const secretKey = "slam_secret"

func GenerateToken(jwtClaims *request2.JWTModel) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	// Set claims
	claims := token.Claims.(jwt.MapClaims)
	claims["data"] = jwtClaims
	claims["exp"] = time.Now().Add(time.Hour * 12).Unix()
	t, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return t, nil
}
func GetTokenClaims(token *jwt.Token) (request2.JWTModel, error) {

	claims := token.Claims.(jwt.MapClaims)
	data := claims["data"].([]byte)
	jwtCustomClaims, err := request2.UnMarshalJWTModel(data)
	if err != nil {
		return request2.JWTModel{}, err
	}
	return jwtCustomClaims, nil
}

//
//func TokenRefresherMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
//	return func(c echo.Context) error {
//		// If the user is not authenticated (no user token data in the context), don't do anything.
//		if c.Get("user") == nil {
//			return next(c)
//		}
//		// Gets user token from the context.
//		u := c.Get("user").(*jwt.Token)
//
//		claims := u.Claims.(*Claims)
//
//		// We ensure that a new token is not issued until enough time has elapsed.
//		// In this case, a new token will only be issued if the old token is within
//		// 15 mins of expiry.
//		if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) < 15*time.Minute {
//			// Gets the refresh token from the cookie.
//			rc, err := c.Cookie(refreshTokenCookieName)
//			if err == nil && rc != nil {
//				// Parses token and checks if it valid.
//				tkn, err := jwt.ParseWithClaims(rc.Value, claims, func(token *jwt.Token) (interface{}, error) {
//					return []byte(GetRefreshJWTSecret()), nil
//				})
//				if err != nil {
//					if err == jwt.ErrSignatureInvalid {
//						c.Response().Writer.WriteHeader(http.StatusUnauthorized)
//					}
//				}
//
//				if tkn != nil && tkn.Valid {
//					// If everything is good, update tokens.
//					_ = GenerateTokensAndSetCookies(&user.User{
//						Name:  claims.Name,
//					}, c)
//				}
//			}
//		}
//
//		return next(c)
//	}
//}
