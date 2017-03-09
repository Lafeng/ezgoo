package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"

	log "github.com/Lafeng/ezgoo/glog"
)

var (
	bad_cr = fmt.Errorf("cr")
	reSig  = regexp.MustCompile(`sig=[^&'"=]+`)
)

func (s *Session) avoidCountryRedirect(xReq *PxReq, w http.ResponseWriter) (err error) {
	defer func() {
		if e := recover(); e != nil {
			dumpError(e)
			switch e.(type) {
			case error:
				err = e.(error)
			default:
				err = fmt.Errorf("%v", e)
			}
		}
	}()
	setPrefDom(xReq, w, s.plainHost)
	return
}

func setPrefDom(xReq *PxReq, w http.ResponseWriter, host string) {
	var req *http.Request
	var resp *http.Response
	var body string

	// remove client old cookies
	xReq.header.Del("Cookie")
	xReq.header.Del("Accept-Encoding")

	baseUrl := default_protocol + default_host
	ncrUrl := baseUrl + "/?gfe_rd=cr&gws_rd=cr"
	req, _ = http.NewRequest("GET", ncrUrl, nil)
	req.Header = xReq.header // use client header
	resp, body = httpCallEx(req, false)

	matches := reSig.FindStringSubmatch(body)
	if matches == nil {
		log.Infoln(body)
		panic("sig not found")
	}

	sig := matches[0]
	setprefUrl := fmt.Sprintf("%s/setprefdomain?prefdom=US&prev=%s&%s", baseUrl, url.QueryEscape(ncrUrl), sig)
	req, _ = http.NewRequest("GET", setprefUrl, nil)
	req.Header = xReq.header

	nid, nidFound := extractNID(resp.Cookies())
	if nidFound {
		req.Header.Set("Cookie", cookieString(nid, nil, false))
	} // else panic ?
	resp, _ = httpCallEx(req, true)

	nid, nidFound = extractNID(resp.Cookies())
	if !nidFound {
		dumpHeader(fmt.Sprintf("resp[%s]->%s", resp.Status, req.URL), resp.Header)
		panic("nid not found")
	} else {
		nid.HttpOnly = true
		w.Header().Set("Set-Cookie", cookieString(nid, &host, true))
	}
	w.Header().Set("Location", "/")
	w.WriteHeader(302)
}

func httpCallEx(req *http.Request, ignoreRd bool) (resp *http.Response, body string) {
	var err error
	resp, err = http_client.Do(req)
	if err != nil {
		if e, y := err.(*url.Error); y && e.Err == err30xRedirect && ignoreRd {
			err = nil
		} else {
			panic(err)
		}
	}

	defer resp.Body.Close()
	var b []byte
	b, err = ioutil.ReadAll(resp.Body)
	if b != nil {
		body = string(b)
	}
	if !consumeError(&err) {
		log.Warningln(err)
	}
	return
}

func extractNID(cookies []*http.Cookie) (nid *http.Cookie, found bool) {
	for _, ck := range cookies {
		if ck.Name == "NID" {
			found = true
			nid = ck
			return
		}
	}
	return
}
