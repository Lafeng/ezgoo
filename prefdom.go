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
	reSig  = regexp.MustCompile("sig=[^&]+")
)

func avoidCountryRedirect(xReq *PxReq, w http.ResponseWriter) (err error) {
	defer func() {
		if e := recover(); e != nil {
			switch e.(type) {
			case error:
				err = e.(error)
			default:
				err = fmt.Errorf("%v", e)
			}
		}
	}()
	setPrefDom(xReq, w)
	return
}

func setPrefDom(xReq *PxReq, w http.ResponseWriter) {
	var req *http.Request
	var resp *http.Response
	var err error
	// remove client old cookies
	xReq.header.Del("Cookie")
	xReq.header.Del("Accept-Encoding")

	baseUrl := default_protocol + default_host
	ncrUrl := baseUrl + "/?gfe_rd=cr&gws_rd=cr"
	req, _ = http.NewRequest("GET", ncrUrl, nil)
	req.Header = xReq.header // use client header
	resp, err = http_client.Do(req)
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()

	matches := reSig.FindStringSubmatch(string(body))
	if matches == nil {
		log.Infoln(string(body))
		panic("sig not found")
	}
	sig := matches[0]
	setprefUrl := fmt.Sprintf("%s/setprefdomain?prefdom=US&prev=%s&%s", baseUrl, url.QueryEscape(ncrUrl), sig)
	req, _ = http.NewRequest("GET", setprefUrl, nil)
	req.Header = xReq.header
	nid, nidFound := extractNID(resp.Cookies())
	if nidFound {
		req.Header.Set("Cookie", nid.Name+"="+nid.Value)
	}
	resp, err = http_client.Do(req)
	if err != nil {
		// must be 30x
		if e, y := err.(*url.Error); y && e.Err == err30xRedirect {
			err = nil
		} else {
			panic(err)
		}
	}

	defer resp.Body.Close()
	nid, nidFound = extractNID(resp.Cookies())
	if !nidFound {
		dumpHeader(fmt.Sprintf("resp[%s] %s", resp.Request.URL, resp.Status), resp.Header)
		panic("nid not found")
	} else {
		http.SetCookie(w, nid)
	}
	w.Header().Set("Location", "/")
	w.WriteHeader(302)
}

func extractNID(cookies []*http.Cookie) (nid *http.Cookie, found bool) {
	for _, ck := range cookies {
		if ck.Name == "NID" {
			ck.Domain = NULL
			ck.Path = NULL
			ck.HttpOnly = true
			found = true
			nid = ck
			return
		}
	}
	return
}
