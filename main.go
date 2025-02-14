package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"http-server/internal/auth"
	"http-server/internal/database"
	"http-server/internal/handlejson"
	"log"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	secret         string
	polkaKey       string
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	secret := os.Getenv("SECRET")
	polkaKey := os.Getenv("POLKAKEY")
	port := ":8080"

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalln(err)
	}
	dbQueries := database.New(db)

	apiConf := apiConfig{
		fileserverHits: atomic.Int32{},
		dbQueries:      dbQueries,
		secret:         secret,
		polkaKey:       polkaKey,
	}

	serveMux := http.NewServeMux()
	appHandler := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	serveMux.Handle("/app/", apiConf.middlewareMetricsInc(appHandler))
	serveMux.HandleFunc("GET /api/healthz", apiHandler)
	serveMux.HandleFunc("GET /api/chirps", apiConf.getChirpsHandler)
	serveMux.HandleFunc("GET /api/chirps/{chirpID}", apiConf.getSingleChirpHandler)
	serveMux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)
	serveMux.HandleFunc("POST /api/users", apiConf.createUserHandler)
	serveMux.HandleFunc("PUT /api/users", apiConf.updateUserHandler)
	serveMux.HandleFunc("POST /api/login", apiConf.loginHandler)
	serveMux.HandleFunc("POST /api/refresh", apiConf.refreshHandler)
	serveMux.HandleFunc("POST /api/revoke", apiConf.revokeHandler)
	serveMux.HandleFunc("POST /api/chirps", apiConf.createChirpsHandler)
	serveMux.HandleFunc("DELETE /api/chirps/{chirpID}", apiConf.deleteChirpsHandler)
	serveMux.HandleFunc("GET /admin/metrics", apiConf.hitsHandler)
	serveMux.HandleFunc("POST /admin/reset", apiConf.resetHandler)
	serveMux.HandleFunc("POST /api/polka/webhooks", apiConf.webhookHandler)
	server := http.Server{
		Handler: serveMux,
		Addr:    port,
	}
	fmt.Println("starting server.")
	err = server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}
}

func apiHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Add("Content-Type", "text/plain; charset=utf-8")
	res.WriteHeader(200)
	codedBody, err := json.Marshal("OK")
	if err != nil {
		log.Fatalf(err.Error())
	}
	res.Write(codedBody)
}

func (ac *apiConfig) hitsHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Add("Content-Type", "text/html")
	htmlText := fmt.Sprintf(`
		<html>
			<body>
				<h1>Welcome, Chirpy Admin</h1>
				<p>Chirpy has been visited %d times!</p>
			</body>
		</html>
	`, ac.fileserverHits.Load())
	res.Write([]byte(htmlText))
}

func (ac *apiConfig) resetHandler(res http.ResponseWriter, req *http.Request) {
	platform := os.Getenv("PLATFORM")
	if platform != "DEV" {
		handlejson.RespondWithError(res, 403, "access forbidden")
	}

	_, err := ac.dbQueries.DeleteAllUser(context.Background())
	if err != nil {
		fmt.Println("error while deleting users from db:")
		fmt.Println(err)
	}
	ac.fileserverHits.Store(0)

}

func (ac *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		ac.fileserverHits.Add(1)
		next.ServeHTTP(res, req)
	})
}

func validateChirpHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	decodedBody, err := handlejson.GetDecodedBody[handlejson.DefaultBody](req.Body)
	if err != nil {
		handlejson.RespondWithError(res, 500, "error while decoding body")
		return
	}
	if len(decodedBody.Body) > 140 {
		handlejson.RespondWithError(res, 400, "Chirp is too long")
		return
	}
	profaneWords := []string{
		"kerfuffle",
		"sharbert",
		"fornax",
	}
	splitedBody := strings.Split(decodedBody.Body, " ")
	const replaceWith = "****"
	for i, word := range splitedBody {
		if slices.Contains(profaneWords, strings.ToLower(word)) {
			splitedBody[i] = replaceWith
		}
	}
	cleanedBody := strings.Join(splitedBody, " ")

	handlejson.RespondWithJSON(res, 200, map[string]string{
		"cleaned_body": cleanedBody,
	})
}

func (ac *apiConfig) loginHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	decodedBody, err := handlejson.GetDecodedBody[handlejson.LoginBody](req.Body)
	if err != nil {
		handlejson.RespondWithError(res, 500, "error while decoding body")
		return
	}
	user, err := ac.dbQueries.FindUserByMail(context.Background(), decodedBody.Email)
	if err != nil {
		handlejson.RespondWithError(res, 401, "Incorrect email or password")
		return
	}
	err = auth.CheckPasswordHash(decodedBody.Password, user.HashedPassword)
	if err != nil {
		handlejson.RespondWithError(res, 401, "Incorrect email or password")
		return
	}
	token, err := auth.MakeJWT(user.ID, ac.secret)
	if err != nil {
		handlejson.RespondWithError(res, 500, "Error while creating token")
		return
	}
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		handlejson.RespondWithError(res, 500, "Error while refresh token")
		return
	}
	const refreshTokenExpiresAfter = time.Hour * 24 * 60
	refreshTokenParams := database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(refreshTokenExpiresAfter),
		RevokedAt: sql.NullTime{Valid: false},
	}
	ac.dbQueries.CreateRefreshToken(context.Background(), refreshTokenParams)
	handlejson.RespondWithJSON(res, 200, map[string]any{
		"id":            user.ID.String(),
		"created_at":    user.CreatedAt.String(),
		"updated_at":    user.CreatedAt.String(),
		"email":         user.Email,
		"token":         token,
		"refresh_token": refreshToken,
		"is_chirpy_red": user.IsChirpyRed,
	})
}

func (ac *apiConfig) refreshHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	passedToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		handlejson.RespondWithError(res, 500, "Error while getting auth")
		return
	}
	dbToken, err := ac.dbQueries.GetRefreshToken(context.Background(), passedToken)
	if err != nil {
		fmt.Println("passedToken that failed: ")
		fmt.Println(passedToken)
		handlejson.RespondWithError(res, 401, "Token not found")
		return
	}
	if dbToken.RevokedAt.Valid || time.Now().After(dbToken.ExpiresAt) {
		handlejson.RespondWithError(res, 401, "Token revoked or expired")
		return
	}
	token, err := auth.MakeJWT(dbToken.UserID, ac.secret)
	if err != nil {
		handlejson.RespondWithError(res, 500, "Error while creating token")
		return
	}
	handlejson.RespondWithJSON(res, 200, map[string]string{
		"token": token,
	})
}

func (ac *apiConfig) revokeHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	passedToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		handlejson.RespondWithError(res, 500, "Error while getting auth")
		return
	}
	_, err = ac.dbQueries.RevokeRefreshToken(context.Background(), passedToken)
	if err != nil {
		handlejson.RespondWithError(res, 500, "Error while updating")
		return
	}

	handlejson.RespondWithJSON(res, 204, nil)
}

func (ac *apiConfig) createUserHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	decodedBody, err := handlejson.GetDecodedBody[handlejson.CreateUserBody](req.Body)
	if err != nil {
		handlejson.RespondWithError(res, 500, "error while decoding body")
		return
	}
	email := decodedBody.Email
	hashedPassword, err := auth.HashPassword(decodedBody.Password)
	if err != nil {
		handlejson.RespondWithError(res, 500, "error while hashing password")
		return
	}
	sqlReq := database.CreateUserParams{
		Email:          email,
		HashedPassword: hashedPassword,
	}
	dbUser, err := ac.dbQueries.CreateUser(context.Background(), sqlReq)
	if err != nil {
		handlejson.RespondWithError(res, 500, "error while creating user")
		return
	}

	handlejson.RespondWithJSON(res, 201, map[string]any{
		"id":            dbUser.ID.String(),
		"created_at":    dbUser.CreatedAt.String(),
		"updated_at":    dbUser.UpdatedAt.String(),
		"email":         dbUser.Email,
		"is_chirpy_red": dbUser.IsChirpyRed,
	})
}

func (ac *apiConfig) updateUserHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	usersToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		handlejson.RespondWithError(res, 401, "Unautorized")
		return
	}
	userId, err := auth.ValidateJWT(usersToken, ac.secret)
	if err != nil {
		handlejson.RespondWithError(res, 401, "Unautorized")
		return
	}
	decodedBody, err := handlejson.GetDecodedBody[handlejson.UpdateUserBody](req.Body)
	if err != nil {
		handlejson.RespondWithError(res, 500, "error while decoding body")
		return
	}
	var databaseUser database.User
	if decodedBody.Email != nil {
		updateEmailParams := database.UpdateUsersEmailParams{
			ID:    userId,
			Email: *decodedBody.Email,
		}
		databaseUser, err = ac.dbQueries.UpdateUsersEmail(context.Background(), updateEmailParams)
		if err != nil {
			handlejson.RespondWithError(res, 500, "error while updating email")
			return
		}
	}
	if decodedBody.Password != nil {
		hashedPass, err := auth.HashPassword(*decodedBody.Password)
		if err != nil {
			handlejson.RespondWithError(res, 500, "error while updating password")
			return
		}
		updatePassParams := database.UpdateUsersPasswordParams{
			ID:             userId,
			HashedPassword: hashedPass,
		}
		databaseUser, err = ac.dbQueries.UpdateUsersPassword(context.Background(), updatePassParams)
	}

	handlejson.RespondWithJSON(res, 200, map[string]any{
		"id":            databaseUser.ID.String(),
		"created_at":    databaseUser.CreatedAt.String(),
		"updated_at":    databaseUser.UpdatedAt.String(),
		"email":         databaseUser.Email,
		"is_chirpy_red": databaseUser.IsChirpyRed,
	})
}

func (ac *apiConfig) createChirpsHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")

	usersToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		handlejson.RespondWithError(res, 401, "Unautorized")
		return
	}
	userId, err := auth.ValidateJWT(usersToken, ac.secret)
	if err != nil {
		handlejson.RespondWithError(res, 401, "Unautorized")
		return
	}
	decodedBody, err := handlejson.GetDecodedBody[handlejson.CreateChirpsBody](req.Body)
	if err != nil {
		handlejson.RespondWithError(res, 500, "error while decoding body")
		return
	}
	isValid := isChirpsValid(decodedBody.Body)
	if !isValid {
		handlejson.RespondWithError(res, 400, "invalid chirps")
		return
	}
	cleansedBody := cleanseChirps(decodedBody.Body)
	sqlChirps := database.CreateChirpsParams{
		Body:   cleansedBody,
		UserID: userId,
	}
	dbChirp, err := ac.dbQueries.CreateChirps(context.Background(), sqlChirps)
	if err != nil {
		handlejson.RespondWithError(res, 500, "error while creating chirps")
		return
	}

	handlejson.RespondWithJSON(res, 201, map[string]string{
		"id":         dbChirp.ID.String(),
		"created_at": dbChirp.CreatedAt.String(),
		"updated_at": dbChirp.UpdatedAt.String(),
		"body":       dbChirp.Body,
		"user_id":    dbChirp.UserID.String(),
	})
}

func (ac *apiConfig) deleteChirpsHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	usersToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		handlejson.RespondWithError(res, 401, "Unautorized")
		return
	}
	userId, err := auth.ValidateJWT(usersToken, ac.secret)
	if err != nil {
		handlejson.RespondWithError(res, 401, "Unautorized")
		return
	}

	chirpsId := req.PathValue("chirpID")
	chirpsUUID, err := uuid.Parse(chirpsId)
	if err != nil {
		handlejson.RespondWithError(res, 500, "Error while parsing id")
		return
	}
	dbChirp, err := ac.dbQueries.GetSingleChirps(context.Background(), chirpsUUID)
	if err != nil {
		handlejson.RespondWithError(res, 404, "chirp not found")
		return
	}
	if dbChirp.UserID != userId {
		handlejson.RespondWithError(res, 403, "not authorised for this resource")
		return
	}

	_, err = ac.dbQueries.DeleteChirp(context.Background(), chirpsUUID)
	if err != nil {
		handlejson.RespondWithError(res, 500, "error while deleting")
		return
	}
	handlejson.RespondWithJSON(res, 204, nil)
}

func (ac *apiConfig) getChirpsHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	authorId := req.URL.Query().Get("author_id")
	sorting := req.URL.Query().Get("sort")

	var chirps []database.Chirp
	if authorId == "" {
		localChirps, err := ac.dbQueries.GetChirps(context.Background())
		if err != nil {
			handlejson.RespondWithError(res, 404, "error while getting chirps")
			return
		}
		chirps = localChirps
	} else {
		authorUUID, err := uuid.Parse(authorId)
		if err != nil {
			handlejson.RespondWithError(res, 400, "error while getting uuid")
			return
		}
		localChirps, err := ac.dbQueries.GetAuthorChirps(context.Background(), authorUUID)
		if err != nil {
			handlejson.RespondWithError(res, 404, "error while getting chirps")
			return
		}
		chirps = localChirps
	}

	if sorting == "asc" {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
		})
	} else if sorting == "desc" {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
		})
	}
	returnChirps := []map[string]string{}

	for _, chirp := range chirps {
		returnChirps = append(returnChirps, map[string]string{
			"id":         chirp.ID.String(),
			"created_at": chirp.CreatedAt.String(),
			"updated_at": chirp.UpdatedAt.String(),
			"body":       chirp.Body,
			"user_id":    chirp.UserID.String(),
		})
	}

	handlejson.RespondWithJSON(res, 200, returnChirps)
}

func (ac *apiConfig) getSingleChirpHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	chirpsId := req.PathValue("chirpID")
	fmt.Println(chirpsId)
	chirpsUUID, err := uuid.Parse(chirpsId)
	if err != nil {
		fmt.Println(err)
		handlejson.RespondWithError(res, 400, "error while reading uuid")
		return
	}
	chirp, err := ac.dbQueries.GetSingleChirps(context.Background(), chirpsUUID)
	if err != nil {
		handlejson.RespondWithError(res, 404, "error while getting chirps")
		return
	}

	handlejson.RespondWithJSON(res, 200, map[string]string{
		"id":         chirp.ID.String(),
		"created_at": chirp.CreatedAt.String(),
		"updated_at": chirp.UpdatedAt.String(),
		"body":       chirp.Body,
		"user_id":    chirp.UserID.String(),
	})
}

func (ac *apiConfig) webhookHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	decodedBody, err := handlejson.GetDecodedBody[handlejson.WebhookBody](req.Body)
	if err != nil {
		handlejson.RespondWithError(res, 500, "error while decoding body")
		return
	}
	passedKey, err := auth.GetAPIKey(req.Header)
	if err != nil {
		handlejson.RespondWithError(res, 401, "no key passed")
		return
	}
	if passedKey != ac.polkaKey {
		handlejson.RespondWithError(res, 401, "incorrect key")
		return
	}

	if decodedBody.Event != "user.upgraded" {
		handlejson.RespondWithJSON(res, 204, nil)
		return
	}

	userUUID, err := uuid.Parse(decodedBody.Data.UserID)
	if err != nil {
		handlejson.RespondWithJSON(res, 404, nil)
		return
	}

	_, err = ac.dbQueries.UpgradeUserToChirpy(context.Background(), userUUID)
	if err != nil {
		handlejson.RespondWithJSON(res, 404, nil)
		return
	}
	fmt.Println("endpoint run to the end")
	handlejson.RespondWithJSON(res, 204, nil)
}

func isChirpsValid(chirpsBody string) bool {
	if len(chirpsBody) > 140 {
		return false
	}
	return true
}

func cleanseChirps(chirpsBody string) string {

	profaneWords := []string{
		"kerfuffle",
		"sharbert",
		"fornax",
	}
	splitedBody := strings.Split(chirpsBody, " ")
	const replaceWith = "****"
	for i, word := range splitedBody {
		if slices.Contains(profaneWords, strings.ToLower(word)) {
			splitedBody[i] = replaceWith
		}
	}
	return strings.Join(splitedBody, " ")
}
