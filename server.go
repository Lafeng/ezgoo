package main

import (
	"errors"
	"flag"
	"fmt"
	log "github.com/Lafeng/ezgoo/glog"
	"net"
	"net/http"
	"os"
	"time"
)

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
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

var (
	listen      string
	pid_file    string
	debug       bool
	config      *AppConfig
	http_client *http.Client
	reRules     *ReRules
)

var (
	err30xRedirect = errors.New("redirect")
	errNotAllowed  = errors.New("Not allowed")
)

func init() {
	var logV int
	var dir string
	flag.IntVar(&logV, "v", 1, "log verbose")
	flag.StringVar(&listen, "l", listen, "listen address")
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

	// perfer command arg
	if listen == NULL {
		listen = config.Listen
	}

	ezgoo := &ezgooServer{"http"}
	serv := &http.Server{
		Addr:           listen,
		Handler:        ezgoo,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	ln, err := net.Listen("tcp", serv.Addr)
	abortIf(err)
	defer ln.Close()
	log.Infoln("Listen at", ln.Addr())
	serv.Serve(&tcpKeepAliveListener{ln.(*net.TCPListener)})
}
