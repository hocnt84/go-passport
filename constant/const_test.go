package constant

import "testing"

func TestCodeChallengePlainToString(t *testing.T) {
	cc := CodeChallengePlain
	if cc.String() != "plain" {
		t.Fatal("not valid")
	}
}

func TestCodeChallengeS256ToString(t *testing.T) {
	cc := CodeChallengeS256
	if cc.String() != "S256" {
		t.Fatal("not valid")
	}
}

func TestValidatePlain(t *testing.T) {
	cc := CodeChallengePlain
	if !cc.Validate("plaintest", "plaintest") {
		t.Fatal("not valid")
	}
}

func TestValidateS256(t *testing.T) {
	cc := CodeChallengeS256
	if !cc.Validate("W6YWc_4yHwYN-cGDgGmOMHF3l7KDy7VcRjf7q2FVF-o=", "s256test") {
		t.Fatal("not valid")
	}
}

func TestValidateS256NoPadding(t *testing.T) {
	cc := CodeChallengeS256
	if !cc.Validate("W6YWc_4yHwYN-cGDgGmOMHF3l7KDy7VcRjf7q2FVF-o", "s256test") {
		t.Fatal("not valid")
	}
}

func TestGrantTypePasswordCredentials(t *testing.T) {
	cc := PasswordCredentials
	if cc.String() != "password" {
		t.Fatal("not valid")
	}
}

func TestGrantTypeClientCredentials(t *testing.T) {
	cc := ClientCredentials
	if cc.String() != "client_credentials" {
		t.Fatal("not valid")
	}
}

func TestGrantTypeRefreshing(t *testing.T) {
	cc := Refreshing
	if cc.String() != "refresh_token" {
		t.Fatal("not valid")
	}
}

func TestGrantTypeAuthorizationCode(t *testing.T) {
	cc := AuthorizationCode
	if cc.String() != "authorization_code" {
		t.Fatal("not valid")
	}
}

func TestGrantTypeImplicit(t *testing.T) {
	cc := Implicit
	if cc.String() != "" {
		t.Fatal("not valid")
	}
}

func TestResponseTypeCode(t *testing.T) {
	cc := Code
	if cc.String() != "code" {
		t.Fatal("not valid")
	}
}

func TestResponseTypeToken(t *testing.T) {
	cc := Token
	if cc.String() != "token" {
		t.Fatal("not valid")
	}
}
