package jwt

func getExpiredFromClaims(claims map[string]interface{}, key string) int64 {
	return int64(claims[key].(float64))
}
