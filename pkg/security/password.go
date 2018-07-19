// Copyright 2015 The Cockroach Authors.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package security

import (
	"crypto/sha256"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"os"

	"github.com/cockroachdb/cockroach/pkg/settings"
	"github.com/cockroachdb/errors"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	"golang.org/x/crypto/pbkdf2"
)

// BcryptCost is the cost to use when hashing passwords. It is exposed for
// testing.
//
// BcryptCost should increase along with computation power.
// For estimates, see: http://security.stackexchange.com/questions/17207/recommended-of-rounds-for-bcrypt
// For now, we use the library's default cost.
var BcryptCost = bcrypt.DefaultCost

// ErrEmptyPassword indicates that an empty password was attempted to be set.
var ErrEmptyPassword = errors.New("empty passwords are not permitted")

// ErrPasswordTooShort indicates that a client provided a password
// that was too short according to policy.
var ErrPasswordTooShort = errors.New("password too short")

var sha256NewSum = sha256.New().Sum(nil)

// TODO(mjibson): properly apply SHA-256 to the password. The current code
// erroneously appends the SHA-256 of the empty hash to the unhashed password
// instead of actually hashing the password. Fixing this requires a somewhat
// complicated backwards compatibility dance. This is not a security issue
// because the round of SHA-256 was only intended to achieve a fixed-length
// input to bcrypt; it is bcrypt that provides the cryptographic security, and
// bcrypt is correctly applied.
func appendEmptySha256(password string) []byte {
	// In the past we incorrectly called the hash.Hash.Sum method. That
	// method uses its argument as a place to put the current hash:
	// it does not add its argument to the current hash. Thus, using
	// h.Sum([]byte(password))) is the equivalent to the below append.
	return append([]byte(password), sha256NewSum...)
}

// CompareHashAndPassword tests that the provided bytes are equivalent to the
// hash of the supplied password. If they are not equivalent, returns an
// error.
func CompareHashAndPassword(hashedPassword []byte, password string) error {
	salt := hashedPassword[:16]
	hash := hashedPassword[16:]
	pass_hash := []byte(pbkdf2.Key([]byte(password), salt, 32768, 32, sha256.New))

	if subtle.ConstantTimeCompare(hash, pass_hash) != 1 {
		return errors.New("security/password: hashedPassword is not the hash of the given password")
	}

	return nil
}

// HashPassword takes a raw password and returns a PBKDF2 hashed password.
func HashPassword(password string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)

	if err != nil {
		return nil, err
	}

	hash := pbkdf2.Key([]byte(password), salt, 32768, 32, sha256.New)
	return []byte(append(salt, hash...)), nil
}

// PromptForPassword prompts for a password.
// This is meant to be used when using a password.
func PromptForPassword() (string, error) {
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	// Make sure stdout moves on to the next line.
	fmt.Print("\n")

	return string(password), nil
}

// MinPasswordLength is the cluster setting that configures the
// minimum SQL password length.
var MinPasswordLength = settings.RegisterIntSetting(
	"server.user_login.min_password_length",
	"the minimum length accepted for passwords set in cleartext via SQL. "+
		"Note that a value lower than 1 is ignored: passwords cannot be empty in any case.",
	1,
	settings.NonNegativeInt,
)
