package main

import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"io"
)

func hashPasswords(password string, userPassword string, passwd string, pwd string, passphrase string) {
	// Direct call to md5.Sum
	hash := md5.Sum([]byte(password))

	// Initialize sha1 and write credential
	h := sha1.New(); h.Write([]byte(userPassword))

	// Initialize md5 and stream string
	hasher := md5.New(); io.WriteString(hasher, passwd)

	// Format hash with sha1.Sum
	hashedPwd := fmt.Sprintf("%x", sha1.Sum([]byte(pwd)))

	// Direct call with passphrase
	passHash := md5.Sum([]byte(passphrase))

	_ = hash
	_ = h
	_ = hasher
	_ = hashedPwd
	_ = passHash
}
