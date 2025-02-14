-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: FindUser :one
SELECT * FROM users WHERE id=$1;

-- name: FindUserByMail :one
SELECT * FROM users WHERE email=$1;

-- name: DeleteAllUser :many
DELETE FROM users
RETURNING *;

-- name: UpdateUsersEmail :one
UPDATE users SET email=$1 WHERE id=$2
RETURNING *;

-- name: UpdateUsersPassword :one
UPDATE users SET hashed_password=$1 WHERE id=$2
RETURNING *;

-- name: UpgradeUserToChirpy :one
UPDATE users SET is_chirpy_red=true WHERE id=$1
RETURNING *;