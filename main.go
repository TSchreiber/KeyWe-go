package keywe

import (
    b64 "encoding/base64"
    "context"
    "crypto"
    "encoding/json"
    "errors"
    "fmt"
    "github.com/hashicorp/cap/jwt"
    "io"
    "net/http"
    "strings"
    "time"

)

type Verifier struct {
    keyStore map[string]crypto.PublicKey
    Keywe_url string
}

func NewVerifier(keywe_url string) *Verifier {
    v := &Verifier{
        keyStore: make(map[string]crypto.PublicKey),
        Keywe_url: keywe_url,
    }
    return v
}

func (v *Verifier) getKey(kid string) (crypto.PublicKey,error) {
    if v.keyStore[kid] != nil {
        return v.keyStore[kid], nil
    }

    key_url := fmt.Sprintf("%s/public_key?kid=%s&format=PEM", v.Keywe_url, kid)

    keywe_res, err := http.Get(key_url)
    if err != nil {
        return nil, errors.New(fmt.Sprintf(
        "Failure: could not authenticate user because the request for the " +
        "resource at, `%s` returned the error message: %s", key_url, err))
    }

    res_body, err := io.ReadAll(keywe_res.Body)
    if err != nil {
        return nil, errors.New(fmt.Sprintf(
        "Failure: could not authenticate user because the call to the " +
        "KeyWe service, `%s/public_key` returned an unexpected response. " +
        "Error message: %s", v.Keywe_url, err))
    }

    pk_PEM, err := jwt.ParsePublicKeyPEM(res_body)
    if err != nil {
        return nil, err
    }

    v.keyStore[kid] = pk_PEM
    return pk_PEM, nil
}

func (v *Verifier) Verify(token string) (map[string]interface{},error) {
    token_header_length := strings.Index(token,".")
    if token_header_length == -1 {
        return nil, errors.New("Could not authenticate user because the token is not formated correctly")
    }
    token_header_str := token[:token_header_length]
    token_header_bytes, err := b64.StdEncoding.DecodeString(token_header_str)
    if err != nil {
        return nil, err
    }

    type TokenHeader struct {
        Kid string
        Alg string
    }
    var token_header TokenHeader
    err = json.Unmarshal(token_header_bytes, &token_header)
    if err != nil {
        return nil, errors.New(fmt.Sprintf(
        "Could not parse token header, error message: %s", err))
    }
    kid := token_header.Kid

    pk_PEM, err := v.getKey(kid)
    if err != nil {
        return nil, err
    }

    keySet, err := jwt.NewStaticKeySet([]crypto.PublicKey{pk_PEM})
    if err != nil {
        return nil, err
    }

    ctx := context.Background()
    claims, err := keySet.VerifySignature(ctx, token)
    if err != nil {
        return nil, err
    }
    exp := time.UnixMilli(int64(claims["exp"].(float64)))
    if time.Now().After(exp) {
        return nil, errors.New("Token is expired")
    }

    return claims, nil
}
