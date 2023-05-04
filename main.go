package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/machinebox/graphql"
)

type ChallengeRes struct {
	Challenge struct {
		Text string
	} `graphql:"challenge(request: $request)"`
}

type ChallengeRequest struct {
	Address string `json:"address"`
}

type EIP4361Request struct {
	EIP191Message string `json:"message,omitempty"`
	Signature     string `json:"signature,omitempty"`
}

func main() {
	domain := "memo.io"

	address := flag.String("address", "0x51632235cc673a788E02B30B9F16F7B1D300194C", "the login address")
	nonce := flag.String("nonce", "b0fb86116a9d914f6ec41c87baf748d64c1f19f7bd3abf1d1cc7fc0e5627c8c1", "the login nonce")
	secretKey := flag.String("sk", "", "the sk to signature")

	flag.Parse()

	// eth login
	hash := crypto.Keccak256([]byte(*address), []byte(*nonce), []byte(domain))
	fmt.Println("sk length:", len(*secretKey), len([]byte(*secretKey)))
	sk, err := crypto.HexToECDSA(*secretKey)
	if err != nil {
		log.Fatal(err)
	}
	signature, err := crypto.Sign(hash, sk)
	if err != nil {
		log.Fatal(err)
	}
	sig := hexutil.Encode(signature)
	fmt.Println("eth login sig: ", sig)
	fmt.Println()

	// lens login
	text, err := Challenge(*address)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("message:")
	fmt.Println(text)
	hash = crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(text), text)))
	signature, err = crypto.Sign(hash, sk)
	if err != nil {
		log.Fatal(err)
	}
	sig = hexutil.Encode(signature)
	fmt.Println("lens login sig:\n", sig)
}

func Challenge(address string) (string, error) {
	client := graphql.NewClient("https://api.lens.dev")

	req := graphql.NewRequest(`
        query Challenge($request:ChallengeRequest!) {
            challenge(request:$request) {
                text
            }
        }`)

	req.Var("request", ChallengeRequest{Address: address})
	req.Header.Set("Origin", "memo.io")

	var query ChallengeRes
	if err := client.Run(context.Background(), req, &query); err != nil {
		return "", err
	}

	return query.Challenge.Text, nil
}
