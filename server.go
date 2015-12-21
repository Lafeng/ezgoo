package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	log "github.com/Lafeng/ezgoo/glog"
)

var (
	listen      string
	pid_file    string
	debug       bool
	config      *AppConfig
	http_client *http.Client
	reRules     *ReRules
	closeable   []io.Closer
)

var (
	err30xRedirect = errors.New("redirect")
	errNotAllowed  = errors.New("Not allowed")
)

func init() {
	var logV int
	var dir string
	flag.IntVar(&logV, "v", 1, "log verbose")
	flag.StringVar(&listen, "l", listen, "listen address <http>,<https>")
	flag.StringVar(&pid_file, "pid", pid_file, "pid file")
	flag.StringVar(&dir, "dir", dir, "config dir")
	flag.BoolVar(&debug, "debug", debug, "debug")
	flag.Parse()

	log.SetLogOutput(NULL)
	log.SetLogVerbose(logV)
	if dir != NULL {
		// enter into config dir
		abortIf(os.Chdir(dir))
	}

	http_client = &http.Client{
		Transport:     DefaultTransport,
		Timeout:       time.Second * 10,
		CheckRedirect: redirectPolicyFunc,
	}
}

type tcpKeepAliveListener struct {
	net.Listener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	c, err = ln.Listener.Accept()
	if tc, y := c.(*net.TCPConn); y && err == nil {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(3 * time.Minute)
	}
	return
}

var dialer = (&net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 300 * time.Second,
}).Dial

var DefaultTransport http.RoundTripper = &http.Transport{
	Proxy:               nil,
	Dial:                dialer,
	TLSHandshakeTimeout: 5 * time.Second,
	MaxIdleConnsPerHost: 256,
}

func redirectPolicyFunc(req *http.Request, via []*http.Request) error {
	return err30xRedirect
}

func logPidFile() (err error) {
	if pid_file != NULL {
		var pf *os.File
		pf, err = os.OpenFile(pid_file, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
		if pf != nil {
			defer pf.Close()
			fmt.Fprintf(pf, "%d", os.Getpid())
		}
	}
	return
}

func abortIf(e interface{}) {
	if e != nil {
		log.Fatalln(e)
	}
}

func main() {
	var err error

	err = logPidFile()
	abortIf(err)
	config, err = initAppConfig()
	abortIf(err)
	reRules, err = initReRules()
	abortIf(err)

	var listenAddrs = make([]string, 2)
	copy(listenAddrs, strings.Split(listen, ","))
	for i, s := range config.servers {
		go startServer(s, listenAddrs[i])
	}
	waitSignal()
}

func startServer(s *AppServ, addr string) {
	var proto = "https"
	var ezgoo = &ezgooServer{proto[:4+s.tlType]}
	if addr == NULL {
		addr = s.Listen
	}

	serv := &http.Server{
		Handler:        ezgoo,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	ln, err := net.Listen("tcp", addr)
	abortIf(err)

	if s.cert != nil {
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{*s.cert}}
		ln = tls.NewListener(ln, tlsConfig)
	}

	closeable = append(closeable, ln)
	defer ln.Close()

	log.Infoln("Listen at", ln.Addr())
	serv.Serve(&tcpKeepAliveListener{ln})
}

func waitSignal() {
	var sigChan = make(chan os.Signal)
	USR2 := syscall.Signal(12) // fake signal-USR2 for windows
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, USR2)

	for sig := range sigChan {
		switch sig {
		case syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM:
			log.Exitln("Terminated by", sig)
			for _, item := range closeable {
				item.Close()
			}
			return
		default:
			log.Infoln("Ingore signal", sig)
		}
	}
}
