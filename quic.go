// Package quic provides a QUIC based transport
package quic

import (
	"context"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/unistack-org/micro/v3/network/transport"
)

type quicSocket struct {
	s   quic.Session
	st  quic.Stream
	enc *gob.Encoder
	dec *gob.Decoder
}

type quicTransport struct {
	opts transport.Options
}

type quicClient struct {
	*quicSocket
	t    *quicTransport
	opts transport.DialOptions
}

type quicListener struct {
	l    quic.Listener
	t    *quicTransport
	opts transport.ListenOptions
}

func (q *quicClient) Close() error {
	return q.quicSocket.st.Close()
}

func (q *quicSocket) Recv(m *transport.Message) error {
	return q.dec.Decode(&m)
}

func (q *quicSocket) Send(m *transport.Message) error {
	// set the write deadline
	if err := q.st.SetWriteDeadline(time.Now().Add(time.Second * 10)); err != nil {
		return err
	}
	// send the data
	return q.enc.Encode(m)
}

func (q *quicSocket) Close() error {
	return q.s.CloseWithError(0, "")
}

func (q *quicSocket) Local() string {
	return q.s.LocalAddr().String()
}

func (q *quicSocket) Remote() string {
	return q.s.RemoteAddr().String()
}

func (q *quicListener) Addr() string {
	return q.l.Addr().String()
}

func (q *quicListener) Close() error {
	return q.l.Close()
}

func (q *quicListener) Accept(fn func(transport.Socket)) error {
	for {
		s, err := q.l.Accept(context.TODO())
		if err != nil {
			return err
		}

		stream, err := s.AcceptStream(context.TODO())
		if err != nil {
			continue
		}

		go func() {
			fn(&quicSocket{
				s:   s,
				st:  stream,
				enc: gob.NewEncoder(stream),
				dec: gob.NewDecoder(stream),
			})
		}()
	}
}

func (q *quicTransport) Init(opts ...transport.Option) error {
	for _, o := range opts {
		o(&q.opts)
	}
	return nil
}

func (q *quicTransport) Options() transport.Options {
	return q.opts
}

func (q *quicTransport) Dial(ctx context.Context, addr string, opts ...transport.DialOption) (transport.Client, error) {
	options := transport.NewDialOptions(opts...)

	config := q.opts.TLSConfig
	if config == nil {
		config = &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		}
	}
	s, err := quic.DialAddr(addr, config, &quic.Config{
		MaxIdleTimeout: time.Minute * 2,
		KeepAlive:      true,
	})
	if err != nil {
		return nil, err
	}

	st, err := s.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}

	enc := gob.NewEncoder(st)
	dec := gob.NewDecoder(st)

	return &quicClient{
		&quicSocket{
			s:   s,
			st:  st,
			enc: enc,
			dec: dec,
		},
		q,
		options,
	}, nil
}

func (q *quicTransport) Listen(ctx context.Context, addr string, opts ...transport.ListenOption) (transport.Listener, error) {
	options := transport.NewListenOptions(opts...)

	config := q.opts.TLSConfig
	if config == nil {
		return nil, fmt.Errorf("must provide valid tls cert")
		/*
			cfg, err := utls.Certificate(addr)
			if err != nil {
				return nil, err
			}
			config = &tls.Config{
				Certificates: []tls.Certificate{cfg},
				NextProtos:   []string{"http/1.1"},
			}
		*/
	}

	l, err := quic.ListenAddr(addr, config, &quic.Config{KeepAlive: true})
	if err != nil {
		return nil, err
	}

	return &quicListener{
		l:    l,
		t:    q,
		opts: options,
	}, nil
}

func (q *quicTransport) String() string {
	return "quic"
}

func NewTransport(opts ...transport.Option) transport.Transport {
	return &quicTransport{
		opts: transport.NewOptions(opts...),
	}
}
