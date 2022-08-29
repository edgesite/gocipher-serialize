//go:build go1.19

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
)

func main() {
	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		panic(err)
	}
	tlsCert, err := tls.LoadX509KeyPair("selfsign.crt", "selfsign.key")
	if err != nil {
		log.Fatalf("tls.LoadX509KeyPair: %v", err)
	}
	c, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("tls: loaded certificate:", c.Subject)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Println("conn", conn)
		go func() {
			t := tls.Conn{}
			fmt.Println(t)
			tc := tls.Server(conn, &tls.Config{
				Certificates:       []tls.Certificate{tlsCert},
				MinVersion:         tls.VersionTLS10,
				MaxVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
			})
			bytes := make([]byte, 1024)
			n, err := tc.Read(bytes)
			if err != nil {
				fmt.Println(err)
			}
			bytes = bytes[:n]

			fmt.Println(tc.Write([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s\r\n", len(bytes)*2+6+10, string(bytes)))))
			pc := FromTlsConn(tc)
			tc2 := pc.ToTlsConn(conn)
			fmt.Println(tc2.Write([]byte(fmt.Sprintf("2nd write:\r\n%s\r\n", string(bytes)))))
		}()
	}
}
