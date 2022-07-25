// Copyright (c) 2022
// Author: Jeff Weisberg <tcp4me.com!jaw>
// Created: 2022-Jul-24 15:52 (EDT)
// Function: syslog client (RFC 5424)

package syslog

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// RFC 5424 - base
// RFC 6587 - tcp
// RFC 5426 - udp
// RFC 5425 - tls

const (
	rfc5424time = "2006-01-02T15:04:05.999999Z07:00"
	maxSize     = 8192
	unixSock    = "/dev/log"
)

var defaultPort = map[string]string{
	"udp": "514",
	"tcp": "514", // 6587 3.3 - This protocol has no standardized port assignment
	"tls": "6514",
}

// Structured contains RFC5424 structed data
type Structured struct {
	Name       string            `json:"name"`
	Enterprise string            `json:"enterprise"` // can be a dotted number (eg. 32473.23.9)
	Param      map[string]string `json:"param"`
}

type L struct {
	proto       string // unix, udp, tcp, tls
	addr        string // filename | addr:port
	withLen     bool   // frame encoding includes length (tcp, tls)
	withConnect bool   // connect at init
	legacy      bool   // use legacy bsd format (rfc 3164)
	facility    Priority
	hostname    string
	appName     string
	procId      string
	maxSize     int
	timeout     time.Duration
	retryDelay  time.Duration
	dialer      *net.Dialer
	tlsConf     *tls.Config
	lock        sync.Mutex     // to guard conn
	conn        io.WriteCloser // net.Conn
}

// Message contains a message to transmit
type Message struct {
	time    time.Time
	Message string        `json:"message"`
	SData   []*Structured `json:"structured"`
}

type optFunc func(*L) error

// New creates a new syslog
func New(optfn ...optFunc) (*L, error) {

	l := &L{
		proto:    "unix",
		addr:     unixSock,
		procId:   "-",
		appName:  "-",
		hostname: "-",
		maxSize:  maxSize,
	}

	for _, fn := range optfn {
		err := fn(l)
		if err != nil {
			return nil, err
		}
	}

	if l.dialer == nil {
		l.dialer = &net.Dialer{Timeout: l.timeout}
	}

	if l.withConnect {
		err := l.connect()
		if err != nil {
			return nil, err
		}
	}

	return l, nil
}

// Close closes a syslog when it is no longer needed
func (l *L) Close() {
	l.lock.Lock()
	defer l.lock.Unlock()

	if l.conn != nil {
		l.conn.Close()
		l.conn = nil
	}
}

func (l *L) connect() error {
	l.lock.Lock()
	defer l.lock.Unlock()

	var err error
	var conn io.WriteCloser

	switch l.proto {
	case "udp", "tcp":
		conn, err = l.dialer.Dial(l.proto, l.addr)
	case "tls":
		conn, err = tls.DialWithDialer(l.dialer, "tcp", l.addr, l.tlsConf)
	case "unix":
		conn, err = net.Dial("unixdgram", l.addr)
	case "file":
		conn, err = os.OpenFile(l.addr, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	}

	if err != nil {
		return err
	}

	l.conn = conn
	return nil
}

// Send sends a syslog message
func (l *L) Send(sev Priority, m Message) error {

	m.time = time.Now()
	pkt, err := l.marshal(sev, &m)
	if err != nil {
		return err
	}

	// try + retry
	for i := 0; i < 3; i++ {
		err = l.connect()
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if nc, ok := l.conn.(net.Conn); ok {
			if l.timeout != 0 {
				nc.SetDeadline(time.Now().Add(l.timeout))
			}
		}

		_, err = l.conn.Write([]byte(pkt))
		if err != nil {
			l.conn.Close()
			time.Sleep(10 * time.Millisecond)
			continue
		}
		break
	}

	return err
}

func (l *L) marshal(sev Priority, m *Message) (string, error) {

	prio := l.priority(sev)

	ts := m.time.UTC().Format(rfc5424time)
	var msg string

	if l.legacy {
		// rfc 3164
		msg = fmt.Sprintf("<%d> %s %s %s[%s]: %s", prio, ts, l.hostname,
			l.appName, l.procId, m.cleanMessage())
	} else {
		msg = fmt.Sprintf("<%d>1 %s %s %s %s - %s %s", prio,
			ts, l.hostname, l.appName, l.procId, /* msg-id */
			m.structuredData(), m.cleanMessage())
	}

	if l.maxSize != 0 && len(msg) > l.maxSize {
		msg = msg[0:l.maxSize]
	}

	if l.withLen {
		msg = fmt.Sprintf("%d %s", len(msg), msg)
	}

	return msg, nil
}

func (m *Message) cleanMessage() string {

	s := strings.Map(func(ch rune) rune {
		if ch == '\n' {
			return ' '
		}
		if ch < ' ' {
			return -1
		}
		return ch
	}, m.Message)

	return s
}

func (m *Message) structuredData() string {
	res := bytes.NewBuffer(nil)

	for _, sd := range m.SData {
		if sd.Enterprise == "" {
			fmt.Fprintf(res, "[%s", sd.Name)
		} else {
			fmt.Fprintf(res, "[%s@%s", sd.Name, sd.Enterprise)
		}

		for k, v := range sd.Param {
			fmt.Fprintf(res, ` %s="%s"`, k, sdValue(v))
		}
		fmt.Fprintf(res, "]")
	}

	if res.Len() == 0 {
		return "-"
	}

	return res.String()
}

func sdValue(s string) string {
	// 5424 6.3.3
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `]`, `\]`)
	return s
}

func (l *L) priority(sev Priority) Priority {
	return (l.facility << 3) | sev
}

// TextMessage converts a plain text string into a Message
func TextMessage(txt string) Message {
	return Message{Message: txt}
}

// WithDst specifies a destination to send syslog messages
// proto should be a supported syslog protocol: usp, tcp, tls, unix
func WithDst(proto, addr string) optFunc {
	return func(l *L) error {

		switch proto {
		case "udp", "tcp", "tls":
			var host, port string
			if strings.Contains(addr, ":") {
				h, p, err := net.SplitHostPort(addr)
				if err != nil {
					return fmt.Errorf("cannot parse dst addr '%s': %v", addr, err)
				}
				host, port = h, p
			} else {
				host = addr
			}
			if port == "" {
				port = defaultPort[proto]
			}
			l.proto = proto
			l.addr = net.JoinHostPort(host, port)

		case "unix", "file":
			l.proto, l.addr = proto, addr
		default:
			return fmt.Errorf("invalid dst protocol '%s', try udp|tcp|tls|unix", proto)
		}

		switch proto {
		case "tcp", "tls":
			l.withLen = true
		}

		return nil
	}

}

// WithConnect will attempt to establish a connection at init
func WithConnect() optFunc {
	return func(l *L) error {
		l.withConnect = true
		return nil
	}
}

// WithLegacyFormat causes legacy format (rfc 3164) essages to be sent
// not all features are supported using the legacy format
func WithLegacyFormat() optFunc {
	return func(l *L) error {
		l.legacy = true
		return nil
	}
}

// WithTimeout specifies a timeout used while sending
func WithTimeout(dur time.Duration) optFunc {
	return func(l *L) error {
		l.timeout = dur
		return nil
	}
}

// WithHostname specifies the local system name
// typically, the value returned by os.Hostname() should be used
func WithHostname(name string) optFunc {
	return func(l *L) error {
		if name != "" {
			l.hostname = name
		}
		return nil
	}
}

// WithAppName specifies the name of the program
// typically, the value of os.Args(0) should be used
func WithAppName(name string) optFunc {
	return func(l *L) error {
		if name != "" {
			l.appName = name
		}
		return nil
	}
}

// WithProcessId specifies the process id
func WithProcessId(id string) optFunc {
	return func(l *L) error {
		if id != "" {
			l.procId = id
		}
		return nil
	}
}

// WithFacility specifies the syslog facility to use
func WithFacility(fac Priority) optFunc {
	return func(l *L) error {
		l.facility = fac
		return nil
	}
}

// WithFacilityName specifies the name of the syslog facility to use
func WithFacilityName(fac string) optFunc {
	return func(l *L) error {
		f, err := Facility(fac)
		if err != nil {
			return err
		}
		l.facility = f
		return nil
	}
}

// WithTLSConfig specifies a *tls.Config to use when sending over TLS
func WithTLSConfig(cf *tls.Config) optFunc {
	return func(l *L) error {
		l.tlsConf = cf
		return nil
	}
}

// WithDialer specifies a *net.Dialer to use when making network connections
func WithDialer(d *net.Dialer) optFunc {
	return func(l *L) error {
		l.dialer = d
		return nil
	}
}

// WithRetryDelay specifies a delay to wait when retrying
func WithRetryDelay(dur time.Duration) optFunc {
	return func(l *L) error {
		l.retryDelay = dur
		return nil
	}
}

// Debug sends a message at Debug severity
func (l *L) Debug(txt string) error { return l.Send(SevDebug, TextMessage(txt)) }

// Emerg sends a message at Emerg severity
func (l *L) Emerg(txt string) error { return l.Send(SevEmerg, TextMessage(txt)) }

// Err sends a message at Err severity
func (l *L) Err(txt string) error { return l.Send(SevErr, TextMessage(txt)) }

// Info sends a message at Info severity
func (l *L) Info(txt string) error { return l.Send(SevInfo, TextMessage(txt)) }

// Notice sends a message at Notice severity
func (l *L) Notice(txt string) error { return l.Send(SevNotice, TextMessage(txt)) }

// Warning sends a message at Warning severity
func (l *L) Warning(txt string) error { return l.Send(SevWarning, TextMessage(txt)) }
