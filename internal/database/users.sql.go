// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: users.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red
`

type CreateUserParams struct {
	Email          string
	HashedPassword string
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser, arg.Email, arg.HashedPassword)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const deleteAllUser = `-- name: DeleteAllUser :many
DELETE FROM users
RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red
`

func (q *Queries) DeleteAllUser(ctx context.Context) ([]User, error) {
	rows, err := q.db.QueryContext(ctx, deleteAllUser)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []User
	for rows.Next() {
		var i User
		if err := rows.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.Email,
			&i.HashedPassword,
			&i.IsChirpyRed,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const findUser = `-- name: FindUser :one
SELECT id, created_at, updated_at, email, hashed_password, is_chirpy_red FROM users WHERE id=$1
`

func (q *Queries) FindUser(ctx context.Context, id uuid.UUID) (User, error) {
	row := q.db.QueryRowContext(ctx, findUser, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const findUserByMail = `-- name: FindUserByMail :one
SELECT id, created_at, updated_at, email, hashed_password, is_chirpy_red FROM users WHERE email=$1
`

func (q *Queries) FindUserByMail(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRowContext(ctx, findUserByMail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const updateUsersEmail = `-- name: UpdateUsersEmail :one
UPDATE users SET email=$1 WHERE id=$2
RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red
`

type UpdateUsersEmailParams struct {
	Email string
	ID    uuid.UUID
}

func (q *Queries) UpdateUsersEmail(ctx context.Context, arg UpdateUsersEmailParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUsersEmail, arg.Email, arg.ID)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const updateUsersPassword = `-- name: UpdateUsersPassword :one
UPDATE users SET hashed_password=$1 WHERE id=$2
RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red
`

type UpdateUsersPasswordParams struct {
	HashedPassword string
	ID             uuid.UUID
}

func (q *Queries) UpdateUsersPassword(ctx context.Context, arg UpdateUsersPasswordParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUsersPassword, arg.HashedPassword, arg.ID)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const upgradeUserToChirpy = `-- name: UpgradeUserToChirpy :one
UPDATE users SET is_chirpy_red=true WHERE id=$1
RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red
`

func (q *Queries) UpgradeUserToChirpy(ctx context.Context, id uuid.UUID) (User, error) {
	row := q.db.QueryRowContext(ctx, upgradeUserToChirpy, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}
