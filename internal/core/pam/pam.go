// Package pam is used for authentication
package pam

import "github.com/msteinert/pam/v2"

func AuthenticateUser(username, password string) error {
	t, err := pam.StartFunc("qosm", username, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return password, nil
		case pam.PromptEchoOn:
			return username, nil
		default:
			return "", nil
		}
	})
	if err != nil {
		return err
	}
	defer t.End()
	return t.Authenticate(0)
}
