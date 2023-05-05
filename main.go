package main

import (
	"context"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/machinebox/graphql"
)

type Challenge struct {
	Challenge struct {
		Text string
	} `graphql:"challenge(request: $request)"`
}

type ChallengeRequest struct {
	Address string `json:"address"`
}

func main() {
	secretKey := flag.String("sk", "", "the sk to signature")

	flag.Parse()

	privateKey, err := crypto.HexToECDSA(*secretKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	// get MEMO-Middleware challenge message for eth account
	text, err := challenge(address)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("message:\n", text)

	// eip191-signature to sign for eth account
	hash := crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(text), text)))
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	sig := hexutil.Encode(signature)
	fmt.Println("login sig:\n", sig)

	// get Lens challenge message
	fmt.Println()
	text, err = challengeLens(address)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Lens message:\n", text)

	hash = crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(text), text)))
	signature, err = crypto.Sign(hash, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	sig = hexutil.Encode(signature)
	fmt.Println("lens login sig:\n", sig)
}

// get message to signature for eth account
func challenge(address string) (string, error) {
	client := &http.Client{Timeout: time.Minute}
	// ip:port should be corresponding to that MEMO-Middleware server is listening
	url := "http://localhost:8081/challenge"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	params := req.URL.Query()
	params.Add("address", address)
	req.URL.RawQuery = params.Encode()
	req.Header.Set("Origin", "https://memo.io")

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("respond code[%d]: %s", res.StatusCode, string(body))
	}

	return string(body), nil
}

// get message to signature for lens account
func challengeLens(address string) (string, error) {
	client := graphql.NewClient("https://api.lens.dev")

	req := graphql.NewRequest(`
        query Challenge($request:ChallengeRequest!) {
            challenge(request:$request) {
                text
            }
        }`)

	req.Var("request", ChallengeRequest{Address: address})
	req.Header.Set("Origin", "memo.io")

	var query Challenge
	if err := client.Run(context.Background(), req, &query); err != nil {
		return "", err
	}

	return query.Challenge.Text, nil
}
