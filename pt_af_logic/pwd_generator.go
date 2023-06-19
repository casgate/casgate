package pt_af_logic

import (
	"crypto/rand"
	"fmt"
	"math/big"
	mathRand "math/rand"
	"strings"
)

const (
	minNum       = 2
	minUpperCase = 2
	minLowerCase = 2
)

func generatePassword(passwordLength int) (string, error) {
	var password strings.Builder

	//Set numeric
	for i := 0; i < minNum; i++ {
		random, err := rand.Int(rand.Reader, big.NewInt(int64(len(numberSet))))
		if err != nil {
			return "", fmt.Errorf("rand.Int: %w", err)
		}
		password.WriteString(string(numberSet[random.Int64()]))
	}

	//Set lowercase
	for i := 0; i < minLowerCase; i++ {
		random, err := rand.Int(rand.Reader, big.NewInt(int64(len(lowerCharSet))))
		if err != nil {
			return "", fmt.Errorf("rand.Int: %w", err)
		}
		password.WriteString(string(lowerCharSet[random.Int64()]))
	}

	//Set uppercase
	for i := 0; i < minUpperCase; i++ {
		random, err := rand.Int(rand.Reader, big.NewInt(int64(len(upperCharSet))))
		if err != nil {
			return "", fmt.Errorf("rand.Int: %w", err)
		}
		password.WriteString(string(upperCharSet[random.Int64()]))
	}

	remainingLength := passwordLength - minNum - minUpperCase - minLowerCase
	for i := 0; i < remainingLength; i++ {
		random, err := rand.Int(rand.Reader, big.NewInt(int64(len(allCharSet))))
		if err != nil {
			return "", fmt.Errorf("rand.Int: %w", err)
		}
		password.WriteString(string(allCharSet[random.Int64()]))
	}
	inRune := []rune(password.String())
	mathRand.Shuffle(len(inRune), func(i, j int) {
		inRune[i], inRune[j] = inRune[j], inRune[i]
	})

	return string(inRune), nil
}
