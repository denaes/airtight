package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// MD5 and SHA-1 are cryptographically broken; use bcrypt or argon2 for passwords.
// Passwords must never be stored using unsalted fast digests.
func safeHashing(password string, salt []byte, fileContent []byte, cacheKey []byte, blob []byte, gitCommitPayload string) {
	// Safe 1: bcrypt password hashing
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Safe 2: argon2id key derivation for password
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Safe 3: sha256 checksum on non-password file content
	checksum := sha256.Sum256(fileContent)

	// Safe 4: md5.Sum on cache key
	cacheKeyHash := md5.Sum(cacheKey)

	// Safe 5: sha1.Sum on arbitrary blob
	sha1Checksum := sha1.Sum(blob)

	// Safe 6: sha1.New for git commit payload hashing
	hasher := sha1.New(); io.WriteString(hasher, gitCommitPayload)

	_ = hash
	_ = key
	_ = checksum
	_ = cacheKeyHash
	_ = sha1Checksum
	_ = hasher
}
