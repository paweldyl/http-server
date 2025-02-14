package handlejson

import (
	"encoding/json"
	"io"
	"net/http"
)

func RespondWithError(res http.ResponseWriter, code int, msg string) {
	res.WriteHeader(code)
	json.NewEncoder(res).Encode(map[string]string{
		"error": msg,
	})
}

func RespondWithJSON(res http.ResponseWriter, code int, payload interface{}) {
	res.WriteHeader(code)
	json.NewEncoder(res).Encode(payload)
}

func GetDecodedBody[expectedStruct any](body io.ReadCloser) (expectedStruct, error) {
	decoder := json.NewDecoder(body)
	var decodedBody expectedStruct
	if err := decoder.Decode(&decodedBody); err != nil {
		return decodedBody, err
	}
	return decodedBody, nil
}
