package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go/aws/session"
)

func InvokeAesEncrypt(sess *session.Session, env string, data string) (resp string, err error) {
	fmt.Println("Encryption Program v0.01")

	text := []byte(data)
	key := []byte("ssshhhhhhhhhhh!!!!")

	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher(key)
	// if there are any errors, handle them
	if err != nil {
		fmt.Println(err)
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		fmt.Println(err)
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.

	json.Unmarshal(gcm.Seal(nonce, nonce, text, nil), &resp)

	return
}

func InvokeAesDecrypt(sess *session.Session, env string, data string) (resp string, err error) {
	keyBytes := []byte("12345678901234567890123456789012")
	ivBytes := []byte("1234567890123456")

	fmt.Println("data::", data)

	dataBytes, err := base64.StdEncoding.DecodeString(data)

	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	fmt.Println("len(dataBytes)::", len(dataBytes))
	fmt.Println("aes.BlockSize::", aes.BlockSize)

	if len(dataBytes) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	mode := cipher.NewCBCDecrypter(block, ivBytes)
	mode.CryptBlocks(dataBytes, dataBytes)

	myString := string(dataBytes[:])
	fmt.Println("myString::", myString)

	return "", nil
}

/*
func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
*/
/*
func InvokeAesDecrypt(sess *session.Session, env string, data string) (resp string, err error) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	ciphertext, _ := base64.StdEncoding.DecodeString(data)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	fmt.Println("aes.BlockSize::", aes.BlockSize)
	fmt.Println("len(ciphertext)::", len(ciphertext))

	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)
	fmt.Printf("%s\n", ciphertext)

	myString := hex.EncodeToString(ciphertext)
	fmt.Println("myString::", myString)

	return "", nil
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}
*/
/*
func InvokeAesDecrypt(sess *session.Session, env string, data string) (resp string, err error) {

	fmt.Println("Decryption Program v0.01")
	key := []byte("1234567890123456")
	//salt := []byte("Impassphrasegood")

	fmt.Println("data::", data)

	//buf := &bytes.Buffer{}
	//gob.NewEncoder(buf).Encode(data)
	bs, _ := base64.StdEncoding.DecodeString(data)

	ciphertext := bs
	// if our program was unable to read the file
	// print out the reason why it can't
	if err != nil {
		fmt.Println(err)
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}

	err = json.Unmarshal(plaintext, &resp)
	if err != nil {
		fmt.Println("Error unmarshalling response")
		os.Exit(0)
	}
	return
}
*/
