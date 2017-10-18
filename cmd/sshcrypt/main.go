package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/is/sshcrypt/lib/sshcryptactions"
	"github.com/is/sshcrypt/lib/sshcryptagent"
	"github.com/is/sshcrypt/lib/sshcryptdata"
	"golang.org/x/crypto/ssh"
)

const challengeSize = 64

// App is base interface of application
type App interface {
	init()
	main()
}

// AgentDecrypt application
type AgentDecrypt struct{}

func (app *AgentDecrypt) init() {}

func (app *AgentDecrypt) main() {
	signers, err := sshcryptagent.GetSigners()
	if err != nil {
		fail(err)
	}
	if len(signers) == 0 {
		fail(fmt.Errorf("Error: At least one signer must be provided. Check that your SSH Agent has at least one key added."))
	}

	data, err := ioutil.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		fail(err)
	}

	cipherTextPackages := strings.Split(string(data), "\n")
	if len(cipherTextPackages) == 0 {
		fail(fmt.Errorf("Error: At least one piece of encrypted data must be provided."))
	}
	for _, cipherTextPackage := range cipherTextPackages {
		if len(cipherTextPackage) == 0 {
			continue
		}

		challenge, cipherText, err := sshcryptdata.DecodeChallengeCipherText(cipherTextPackage)
		if err != nil {
			fmt.Println(err)
			return
		}

		for _, signer := range signers {
			sig, err := sshcryptactions.Sign(signer, challenge)
			if err != nil {
				fmt.Println(err)
				return
			}

			clearText, ok, err := sshcryptactions.DecryptWithPassword(sig.Blob, cipherText)
			if err != nil {
				fmt.Println(err)
				return
			}
			if ok {
				os.Stdout.Write(clearText)
				os.Exit(0)
			}
		}
	}

	fmt.Println("Decryption not possible")
	os.Exit(1)
}

// AgentEncrypt application
type AgentEncrypt struct{}

func (app *AgentEncrypt) init() {}

func (app *AgentEncrypt) main() {
	signers, err := sshcryptagent.GetSigners()
	if err != nil {
		fail(err)
	}
	if len(signers) == 0 {
		fail(fmt.Errorf("Error: At least one signer must be provided. Check that your SSH Agent has at least one key added."))
		return
	}

	data, err := ioutil.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		fail(err)
	}

	var cipherTexts []string
	for _, signer := range signers {
		var challenge [challengeSize]byte
		if _, err := rand.Read(challenge[:]); err != nil {
			fail(err)
		}

		sig, err := sshcryptactions.Sign(signer, challenge[:])
		if err != nil {
			fail(err)
		}

		cipherText, err := sshcryptactions.EncryptWithPassword(sig.Blob, data)
		if err != nil {
			fail(err)
		}

		encodedCipherText := sshcryptdata.EncodeChallengeCipherText(challenge[:], cipherText)
		cipherTexts = append(cipherTexts, encodedCipherText)
	}

	fmt.Println(strings.Join(cipherTexts, "\n"))
}

// AgentSign application
type AgentSign struct{}

func (app *AgentSign) init() {}

func (app *AgentSign) main() {
	signers, err := sshcryptagent.GetSigners()
	if err != nil {
		fail(err)
	}
	if len(signers) == 0 {
		fail(fmt.Errorf("Error: At least one signer must be provided. Check that your SSH Agent has at least one key added."))
	}

	data, err := ioutil.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		fail(err)
	}

	var sigs []string
	for _, signer := range signers {
		sig, err := sshcryptactions.Sign(signer, data)
		if err != nil {
			fail(err)
		}
		sigs = append(sigs, sshcryptdata.EncodeSignature(sig))
	}

	fmt.Println(strings.Join(sigs, "\n"))
}

// Encrypt application
type Encrypt struct {
	password string
}

func (app Encrypt) init() {
	password := flag.String("p", "", "Password to use for encryption")
	flag.Parse()
	app.password = *password
}

func (app Encrypt) main() {
	data, err := ioutil.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		fail(err)
	}

	cipherText, err := sshcryptactions.EncryptWithPassword([]byte(app.password), data)
	if err != nil {
		fail(err)
	}

	encodedCipherText := sshcryptdata.EncodeCipherText(cipherText)
	fmt.Println(encodedCipherText)
}

// Decrypt application
type Decrypt struct {
	password string
}

func (app Decrypt) init() {
	password := flag.String("p", "", "Password to use for encryption")
	flag.Parse()
	app.password = *password
}

func (app Decrypt) main() {
	data, err := ioutil.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		fail(err)
	}

	cipherText, err := sshcryptdata.DecodeCipherText(string(data))
	if err != nil {
		fail(err)
	}

	clearText, ok, err := sshcryptactions.DecryptWithPassword([]byte(app.password), cipherText)
	if err != nil {
		fail(err)
	}
	if !ok {
		fail(fmt.Errorf("Decryption not possible"))
	}
	os.Stdout.Write(clearText)
}

// Verify application
type Verify struct {
	sig string
	pk  string
}

func (app *Verify) init() {
	sig := flag.String("s", "", "signature to verify")
	pk := flag.String("k", "", "public-key")
	flag.Parse()
	app.sig = *sig
	app.pk = *pk
}

func (app *Verify) main() {
	var sshSignatures []*ssh.Signature
	for _, sig := range strings.Split(app.sig, "\n") {
		sshSignature, err := sshcryptdata.DecodeSignature(sig)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		sshSignatures = append(sshSignatures, sshSignature)
	}
	if len(sshSignatures) == 0 {
		fmt.Println("Error: At least one signature must be provided.")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var sshPublicKeys []ssh.PublicKey
	for _, pk := range strings.Split(app.pk, "\n") {
		sshPublicKey, err := sshcryptdata.DecodePublicKey(pk)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		sshPublicKeys = append(sshPublicKeys, sshPublicKey)
	}
	if len(sshPublicKeys) == 0 {
		fmt.Println("Error: At least one public key must be provided..")
		flag.PrintDefaults()
		os.Exit(1)
	}

	data, err := ioutil.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, sig := range sshSignatures {
		for _, pk := range sshPublicKeys {
			err = pk.Verify(data, sig)
			if err == nil {
				fmt.Println("Success")
				os.Exit(0)
			}
		}
	}

	fmt.Println("Failed")
	os.Exit(1)
}

func printUsage() {
	fmt.Printf(
		`Usage: sshcrypt [command]
Commands:
	agent-encrypt - Encrypt data using the signature of a random challenge as the key
	agent-decrypt - Decrypt data using the signature of a random challenge as the key
	encrypt       - Encrypt data using a password
	decrypt       - Decrypt data using a password
	agent-sign    - Sign data with the SSH Agent
	verify        - Verify SSH signatures
`)
}

func fail(err error) {
	fmt.Println(err)
	os.Exit(1)
}

func main() {
	if len(os.Args) == 1 {
		printUsage()
		return
	}

	command := os.Args[1]
	var app App

	switch command {
	case "agent-encrypt", "ae":
		app = &AgentEncrypt{}
	case "agent-decrypt", "ad":
		app = &AgentDecrypt{}
	case "encrypt", "e":
		app = &Encrypt{}
	case "decrypt", "d":
		app = &Decrypt{}
	case "agent-sign", "as":
		app = &AgentSign{}
	case "verify", "v":
		app = &AgentSign{}
	default:
		app = nil
	}

	if app == nil {
		printUsage()
	} else {
		app.init()
		app.main()
	}
}
