package handlejson

type DefaultBody struct {
	Body string `json:"body"`
}

type LoginBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type CreateUserBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UpdateUserBody struct {
	Email    *string `json:"email"`
	Password *string `json:"password"`
}

type CreateChirpsBody struct {
	Body string `json:"body"`
}

type WebhookBody struct {
	Event string `json:"event"`
	Data  struct {
		UserID string `json:"user_id"`
	} `json:"data"`
}
