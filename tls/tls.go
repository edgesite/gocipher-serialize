//go:build go1.19

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"reflect"
	"unsafe"
)

type Conn struct {
	// constant
	conn     net.Conn
	isClient bool
	//handshakeFn func(context.Context) error // (*Conn).clientHandshake or serverHandshake

	// handshakeStatus is 1 if the connection is currently transferring
	// application data (i.e. is not currently processing a handshake).
	// handshakeStatus == 1 implies handshakeErr == nil.
	// This field is only to be accessed with sync/atomic.
	handshakeStatus uint32
	// constant after handshake; protected by handshakeMutex
	//handshakeMutex sync.Mutex
	handshakeErr error       // error resulting from handshake
	vers         uint16      // TLS version
	haveVers     bool        // version has been negotiated
	config       *tls.Config // configuration passed to constructor
	// handshakes counts the number of handshakes performed on the
	// connection so far. If renegotiation is disabled then this is either
	// zero or one.
	handshakes       int
	didResume        bool // whether this connection was a session resumption
	cipherSuite      uint16
	ocspResponse     []byte   // stapled OCSP response
	scts             [][]byte // signed certificate timestamps from server
	peerCertificates []*x509.Certificate
	// verifiedChains contains the certificate chains that we built, as
	// opposed to the ones presented by the server.
	verifiedChains [][]*x509.Certificate
	// serverName contains the server name indicated by the client, if any.
	serverName string
	// secureRenegotiation is true if the server echoed the secure
	// renegotiation extension. (This is meaningless as a server because
	// renegotiation is not supported in that case.)
	secureRenegotiation bool
	// ekm is a closure for exporting keying material.
	ekm func(label string, context []byte, length int) ([]byte, error)
	// resumptionSecret is the resumption_master_secret for handling
	// NewSessionTicket messages. nil if config.SessionTicketsDisabled.
	resumptionSecret []byte

	// ticketKeys is the set of active session ticket keys for this
	// connection. The first one is used to encrypt new tickets and
	// all are tried to decrypt tickets.
	//ticketKeys []ticketKey

	// clientFinishedIsFirst is true if the client sent the first Finished
	// message during the most recent handshake. This is recorded because
	// the first transmitted Finished message is the tls-unique
	// channel-binding value.
	clientFinishedIsFirst bool

	// closeNotifyErr is any error from sending the alertCloseNotify record.
	closeNotifyErr error
	// closeNotifySent is true if the Conn attempted to send an
	// alertCloseNotify record.
	closeNotifySent bool

	// clientFinished and serverFinished contain the Finished message sent
	// by the client or server in the most recent handshake. This is
	// retained to support the renegotiation extension and tls-unique
	// channel-binding.
	clientFinished [12]byte
	serverFinished [12]byte

	// clientProtocol is the negotiated ALPN protocol.
	clientProtocol string

	// input/output
	in, out   interface{}  // halfConn
	rawInput  bytes.Buffer // raw input, starting with a record header
	input     bytes.Reader // application data waiting to be read, from rawInput.Next
	hand      bytes.Buffer // handshake data waiting to be read
	buffering bool         // whether records are buffered in sendBuf
	sendBuf   []byte       // a buffer of records waiting to be sent

	// bytesSent counts the bytes of application data sent.
	// packetsSent counts packets.
	bytesSent   int64
	packetsSent int64

	// retryCount counts the number of consecutive non-advancing records
	// received by Conn.readRecord. That is, records that neither advance the
	// handshake, nor deliver application data. Protected by in.Mutex.
	retryCount int

	// activeCall is an atomic int32; the low bit is whether Close has
	// been called. the rest of the bits are the number of goroutines
	// in Conn.Write.
	activeCall int32

	tmp [16]byte
}

func (pc *Conn) ToTlsConn(nc net.Conn) (c *tls.Conn) {
	c = &tls.Conn{}

	rvs := reflect.ValueOf(pc).Elem()
	rts := reflect.TypeOf(pc).Elem()

	rvd := reflect.ValueOf(c).Elem()

	for i := 0; i < rvs.NumField(); i++ {
		field := rts.Field(i)
		v := getUnexportedField(rvs.Field(i))
		if v != nil && v != false && v != 0 {
			setUnexportedField(rvd.FieldByName(field.Name), v)
			fmt.Println(field.Name, v, getUnexportedField(rvd.FieldByName(field.Name)))
		}
	}
	setUnexportedField(rvd.FieldByName("conn"), nc)
	return
}

func FromTlsConn(orig *tls.Conn) *Conn {
	ov := reflect.ValueOf(orig).Elem()
	fmt.Println(ov)
	conn := &Conn{
		handshakeStatus: getUnexportedField(ov.FieldByName("handshakeStatus")).(uint32),
		//handshakeMutex:  sync.Mutex{},
		//handshakeErr:        getUnexportedField(ov.FieldByName("handshakeErr")).(error),
		vers:                getUnexportedField(ov.FieldByName("vers")).(uint16),
		haveVers:            getUnexportedField(ov.FieldByName("haveVers")).(bool),
		config:              getUnexportedField(ov.FieldByName("config")).(*tls.Config),
		handshakes:          getUnexportedField(ov.FieldByName("handshakes")).(int),
		didResume:           getUnexportedField(ov.FieldByName("didResume")).(bool),
		cipherSuite:         getUnexportedField(ov.FieldByName("cipherSuite")).(uint16),
		ocspResponse:        getUnexportedField(ov.FieldByName("ocspResponse")).([]byte),
		scts:                getUnexportedField(ov.FieldByName("scts")).([][]byte),
		peerCertificates:    getUnexportedField(ov.FieldByName("peerCertificates")).([]*x509.Certificate),
		verifiedChains:      getUnexportedField(ov.FieldByName("verifiedChains")).([][]*x509.Certificate),
		serverName:          getUnexportedField(ov.FieldByName("serverName")).(string),
		secureRenegotiation: getUnexportedField(ov.FieldByName("secureRenegotiation")).(bool),
		// ekm:
		resumptionSecret: getUnexportedField(ov.FieldByName("resumptionSecret")).([]byte),

		//ticketKeys: getUnexportedField(ov.FieldByName("ticketKeys")).([]ticketKey),
		clientFinishedIsFirst: getUnexportedField(ov.FieldByName("clientFinishedIsFirst")).(bool),
		//closeNotifyErr:        getUnexportedField(ov.FieldByName("closeNotifyErr")).(error),
		closeNotifySent: getUnexportedField(ov.FieldByName("closeNotifySent")).(bool),
		clientFinished:  getUnexportedField(ov.FieldByName("clientFinished")).([12]byte),
		serverFinished:  getUnexportedField(ov.FieldByName("serverFinished")).([12]byte),
		clientProtocol:  getUnexportedField(ov.FieldByName("clientProtocol")).(string),

		in:        getUnexportedField(ov.FieldByName("in")).(interface{}),
		out:       getUnexportedField(ov.FieldByName("out")).(interface{}),
		rawInput:  getUnexportedField(ov.FieldByName("rawInput")).(bytes.Buffer),
		input:     getUnexportedField(ov.FieldByName("input")).(bytes.Reader),
		hand:      getUnexportedField(ov.FieldByName("hand")).(bytes.Buffer),
		buffering: getUnexportedField(ov.FieldByName("buffering")).(bool),
		sendBuf:   getUnexportedField(ov.FieldByName("sendBuf")).([]byte),

		bytesSent:   getUnexportedField(ov.FieldByName("bytesSent")).(int64),
		packetsSent: getUnexportedField(ov.FieldByName("packetsSent")).(int64),
		retryCount:  getUnexportedField(ov.FieldByName("retryCount")).(int),
		activeCall:  getUnexportedField(ov.FieldByName("activeCall")).(int32),

		tmp: getUnexportedField(ov.FieldByName("tmp")).([16]byte),
	}
	return conn
}

// from https://stackoverflow.com/a/60598827
func getUnexportedField(field reflect.Value) interface{} {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
}

func setUnexportedField(field reflect.Value, value interface{}) {
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).
		Elem().
		Set(reflect.ValueOf(value))
}
