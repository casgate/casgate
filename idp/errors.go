package idp

import "fmt"

type NotImplementedError struct {
	message string
}

func NewNotImplementedError(message string) error {
	return &NotImplementedError{message: message}
}

func (err NotImplementedError) Error() string {
	return err.message
}

type MissingParameterError struct {
	message string
}

func NewMissingParameterError(message string) error {
	return &MissingParameterError{message: message}
}

func (err MissingParameterError) Error() string {
	return err.message
}

type StatusError struct {
	code int
}

func NewStatusError(code int) error {
	return &StatusError{code: code}
}

func (err StatusError) Error() string {
	return fmt.Sprintf("%d", err.code)
}
