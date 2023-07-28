package pwd_generator

import (
	"crypto/rand"
	"fmt"
	"math/big"
	mathRand "math/rand"
	"strings"

	"github.com/casdoor/casdoor/pt_af_logic/types"
)

const (
	minNum       = 2
	minUpperCase = 2
	minLowerCase = 2
)

func GeneratePassword(passwordLength int) (string, error) {
	var password strings.Builder

	//Set numeric
	for i := 0; i < minNum; i++ {
		random, err := rand.Int(rand.Reader, big.NewInt(int64(len(types.NumberSet))))
		if err != nil {
			return "", fmt.Errorf("rand.Int: %w", err)
		}
		password.WriteString(string(types.NumberSet[random.Int64()]))
	}

	//Set lowercase
	for i := 0; i < minLowerCase; i++ {
		random, err := rand.Int(rand.Reader, big.NewInt(int64(len(types.LowerCharSet))))
		if err != nil {
			return "", fmt.Errorf("rand.Int: %w", err)
		}
		password.WriteString(string(types.LowerCharSet[random.Int64()]))
	}

	//Set uppercase
	for i := 0; i < minUpperCase; i++ {
		random, err := rand.Int(rand.Reader, big.NewInt(int64(len(types.UpperCharSet))))
		if err != nil {
			return "", fmt.Errorf("rand.Int: %w", err)
		}
		password.WriteString(string(types.UpperCharSet[random.Int64()]))
	}

	remainingLength := passwordLength - minNum - minUpperCase - minLowerCase
	for i := 0; i < remainingLength; i++ {
		random, err := rand.Int(rand.Reader, big.NewInt(int64(len(types.AllCharSet))))
		if err != nil {
			return "", fmt.Errorf("rand.Int: %w", err)
		}
		password.WriteString(string(types.AllCharSet[random.Int64()]))
	}
	inRune := []rune(password.String())
	mathRand.Shuffle(len(inRune), func(i, j int) {
		inRune[i], inRune[j] = inRune[j], inRune[i]
	})

	return string(inRune), nil
}
