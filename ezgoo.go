package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	log "github.com/Lafeng/ezgoo/glog"
)

const (
	NULL              = ""
	default_protocol  = "https://"
	default_host      = "www.google.com"
	maxAcceptedLength = 2 << 20
)

var (
	reAbuseRedirect = regexp.MustCompile(`ipv\d\.google\.com/sorry`)
)

type JsonObject map[string]interface{}

type ezgooServer struct {
	proto string
}

func outputError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Del("Content-Length")
	if err == errNotAllowed {
		w.WriteHeader(403)
	} else {
		w.WriteHeader(500)
	}
	fmt.Fprintf(w, "Error: %v", err)
}

type Session struct {
	dAddr      string // direct client address
	dProto     string
	dMethod    string
	dUserAgent string
	url        *url.URL
	uri        string // RequestURI with parameters
	body       io.ReadCloser
	aAddr      string
	aProto     string
	aHost      string
	aPort      int
	aMethod    string
	abusing    bool
	redirected bool
}

func (x *ezgooServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	se := NewSession(req)
	if se.Preprocess(w, req) {
		return
	}

	xReq, err := se.buildPxReq(req)
	if err == nil {
		err = se.doProxy(xReq, w)
	}

	if err != nil {
		outputError(w, err)
	}
}

func NewSession(req *http.Request) *Session {
	s := &Session{
		dAddr:      req.RemoteAddr,
		dMethod:    req.Method,
		dUserAgent: req.UserAgent(),
		url:        req.URL,
		uri:        req.RequestURI,
		body:       req.Body,
		aAddr:      req.RemoteAddr,
		aProto:     req.Proto, //???
		aHost:      req.Host,
		aPort:      -1,
		aMethod:    req.Method,
	}
	if config.TrustProxy {
		s.DetermineActualRequest(req)
	}
	log.Infoln("uri", req.RequestURI)
	return s
}

func (s *Session) DetermineActualRequest(req *http.Request) {
	aProto := req.Header.Get("X-Forwarded-Proto")
	if aProto != NULL {
		s.aProto = aProto
	}
	aHost := req.Header.Get("X-Forwarded-Host")
	if aHost != NULL {
		s.aHost = aHost
	}
	aCliAddr := req.Header.Get("X-Forwarded-For")
	if aCliAddr != NULL {
		if pos := strings.Index(aCliAddr, ","); pos > 0 {
			s.aAddr = aCliAddr[:pos]
		} else {
			s.aAddr = aCliAddr
		}
	}
	aPort := req.Header.Get("X-Forwarded-Port")
	if aPort != NULL {
		port, err := strconv.Atoi(aPort)
		if err == nil {
			s.aPort = port
		}
	}
	cf_vistor := req.Header.Get("cf-visitor")
	if cf_vistor != NULL {
		jsonObj := make(JsonObject)
		if err := json.Unmarshal([]byte(cf_vistor), jsonObj); err == nil {
			if scheme := jsonObj["scheme"]; scheme != nil {
				s.aProto = scheme.(string)
			}
		}
	}
}

func (s *Session) Preprocess(w http.ResponseWriter, req *http.Request) (accept bool) {
	switch s.url.Path {
	case "/url":
		next := req.FormValue("url")
		if next != NULL {
			http.Redirect(w, req, next, 307)
			accept = true
			return
		}

	case "/robots.txt":
		w.WriteHeader(200)
		fmt.Fprint(w, robots_response)
		accept = true
		return
		/*
			case "/gen_204":
				w.WriteHeader(204)
				accept = true
		*/
	}
	if s.aMethod == "HEAD" {
		w.WriteHeader(200)
		return true
	}
	if !config.CheckClientRestriction(s, req) {
		outputError(w, errNotAllowed)
		return true
	}
	if config.ForceTls {
		if s.aProto != "https" {
			req.URL.Scheme = "https"
			next := req.URL.String()
			http.Redirect(w, req, next, 301)
			return true
		}
	}

	return
}

type PxReq struct {
	url        *url.URL
	nondefault int
	header     http.Header
	tmpDest    string
}

func (s *Session) buildPxReq(req *http.Request) (xReq *PxReq, err error) {
	var dst *url.URL
	var nondef int
	var uri = s.uri
	var ckNames map[string]bool
	var xHeader = make(http.Header)

	if strings.HasPrefix(uri, "/!") {
		uri = uri[2:]
		ckNames = make(map[string]bool)
		nondef |= 0xf
	} else {
		uri = default_host + uri
	}

	dst, err = url.Parse(default_protocol + uri)
	if err != nil {
		return
	}

	// process in-Header
	// copy header, skip Cookie
	for k, vv := range req.Header {
		switch k {
		case "Referer":
			ref := vv[0]
			if pos := strings.Index(ref, "/!"); pos > 0 {
				ref = default_protocol + ref[pos+2:]
				vv[0] = ref
			} else {
				continue
			}
		case "Cookie", "Origin":
			continue
		default:
			if strings.HasPrefix(k, "X-") {
				continue
			}
		}
		xHeader[k] = vv
	}

	// process in-Cookies
	// copy cookies, skip namesakes if requested to nondefault domain
	var cookies []string
	for _, ck := range req.Cookies() {
		if nondef > 0 {
			if ckNames[ck.Name] {
				if debug {
					log.Warningf("cookie dup??? uri=%s exists=[%s] %s==%s", uri, strings.Join(cookies, "]["), ck.Name, ck.Value)
				}
				continue
			} else {
				ckNames[ck.Name] = true
			}
		}
		// ignore __cookie
		if strings.HasPrefix(ck.Name, "__") {
			continue
		}
		cookies = append(cookies, ck.String())
	}
	if len(cookies) > 0 {
		xHeader.Set("Cookie", strings.Join(cookies, "; "))
	}

	if !config.CheckDomainRestriction(dst.Host) {
		return nil, errNotAllowed
	}

	// ipv[46]
	if nondef > 0 && reAbuseRedirect.MatchString(uri) {
		nondef |= 0xf0
		s.abusing = true
	}

	xHeader.Set("Connection", "keep-alive")
	xHeader.Set("Accept-Encoding", "gzip")

	xReq = &PxReq{
		url:        dst,
		nondefault: nondef,
		header:     xHeader,
	}
	return
}

func (s *Session) doProxy(xReq *PxReq, w http.ResponseWriter) (err error) {
	var req *http.Request
	var resp *http.Response

	req, err = NewRequest(s.dMethod, xReq.url, s.body)
	req.Header = xReq.header

	if log.V(3) {
		dumpHeader("<- Header/ActualReq", req.Header)
	}

	resp, err = http_client.Do(req)

	if log.V(1) {
		if resp != nil {
			log.Infof("%s %s %s [%d] %s", s.aAddr, s.aMethod, s.dUserAgent, resp.StatusCode, xReq.url.String())
		} else {
			log.Infof("%s %s %s [Err] %s", s.aAddr, s.aMethod, s.dUserAgent, xReq.url.String())
		}
	}
	if log.V(3) && resp != nil {
		dumpHeader("-> Header/OriginalResp", resp.Header)
	}

	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		if e, y := err.(*url.Error); y {
			s.redirected = e.Err == err30xRedirect
		}
		if s.redirected {
			err = nil
		} else {
			return dumpError(err)
		}
	}

	s.processOutputHeader(xReq, resp, w)

	pMethod := determineHandler(resp.Header.Get("Content-Type"))

	if pMethod == HD_unknown || resp.ContentLength > maxAcceptedLength {
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	} else {
		err = pMethod.processText(s, w, resp)
	}
	return
}

func (s *Session) processOutputHeader(xReq *PxReq, resp *http.Response, w http.ResponseWriter) {
	wHeader := w.Header()
	for k, array := range resp.Header {
		switch k {
		case "Set-Cookie":
			continue
		case "Location":
			targetUrl := array[0]
			nextUrl := s.processRedirect(targetUrl)
			if log.V(1) {
				log.Infof("Cook redirection %s -> %s", targetUrl, nextUrl)
			}
			wHeader.Set(k, nextUrl)
		default:
			// Alt-Svc, Alternate-Protocol
			if strings.HasPrefix(k, "Alt") {
				continue
			}
			for _, v := range array {
				wHeader.Add(k, v)
			}
		}
	}
	wHeader.Set("Server", "ezgoo")
	var myDomain string
	var alterCookie = xReq.nondefault == 0xf
	for _, ck := range resp.Cookies() {
		if alterCookie {
			if ck.Domain == NULL || strings.HasPrefix(ck.Domain, ".") {
				ck.Path = fmt.Sprintf("/!%s%s", xReq.url.Host, ck.Path)
			} else {
				ck.Path = fmt.Sprintf("/!%s%s", ck.Domain, ck.Path)
			}
		}
		if myDomain == NULL {
			// domain:port ?
			if pos := strings.IndexByte(s.aHost, ':'); pos > 0 {
				myDomain = s.aHost[:pos]
			} else {
				myDomain = s.aHost
			}
		}
		ck.Domain = myDomain
		if v := ck.String(); v != NULL {
			wHeader.Add("Set-Cookie", v)
		}
		// debug
		if s.redirected && ck.Name == "GOOGLE_ABUSE_EXEMPTION" && xReq.url.Path == "/search" {
			log.Warningln("GOOGLE_ABUSE_EXEMPTION failed")
		}
	}
}

func (s *Session) processRedirect(target string) string {
	uri, _ := url.Parse(target)

	// prevent redirecting to country site
	/*
		if uri.Path == "/" && strings.Contains(uri.RawQuery, "gfe_rd=cr") {
			return "/ncr"
		}
	*/
	if uri.Path == s.url.Path && uri.Host != default_host {
		// new redirect policy
		ref := s.url.RawQuery
		if len(ref) > 0 {
			ref += "&gfe_rd=cr"
		} else {
			ref = "gfe_rd=cr"
		}
		if strings.HasPrefix(uri.RawQuery, ref) {
			params := uri.Query()
			params.Set("gfe_rd", "cr")
			params.Set("gws_rd", "cr")
			return uri.Path + "?" + params.Encode()
		}
	}
	if config.CheckDomainRestriction(uri.Host) {
		// maybe non-default domain
		nondefault := uri.Host != default_host
		if nondefault {
			uri.Path = uri.Host + uri.Path
		}
		// relative url
		uri.Scheme, uri.Host = NULL, NULL
		target = uri.String()
		if nondefault {
			target = "/!" + target
		}
	}
	if len(target) == 0 {
		target = "/"
	}
	return target
}

type Handler int

const (
	HD_unknown    = Handler(0)
	HD_html       = Handler(2)
	HD_javascript = Handler(3)
	HD_css        = Handler(4)
	HD_json       = Handler(5)
)

func determineHandler(contentType string) Handler {
	// Content-Type: application/json; charset=UTF-8
	pos := strings.IndexByte(contentType, '/')
	if pos > 0 {
		contentType = contentType[pos+1:]
		pos = strings.IndexByte(contentType, ';')
		if pos > 0 {
			contentType = contentType[:pos]
		}
	}
	switch contentType {
	case "html":
		return HD_html
	case "json":
		return HD_json
	case "javascript":
		return HD_javascript
	case "css":
		return HD_css
	}
	return HD_unknown
}

func (p Handler) processText(s *Session, w http.ResponseWriter, resp *http.Response) (err error) {
	var (
		zr      *gzip.Reader
		zw      *gzip.Writer
		body    []byte
		gzipped bool   = resp.Header.Get("Content-Encoding") == "gzip"
		reqHost string = resp.Request.URL.Host
		reqPath string = resp.Request.URL.Path
	)
	if resp.ContentLength != 0 && resp.Request.Method != "HEAD" {
		if gzipped {
			zr, err = gzip.NewReader(resp.Body)
			if err == nil {
				body, err = ioutil.ReadAll(zr)
				if !consumeError(&err) {
					return dumpError(err)
				}
			}
		} else {
			body, err = ioutil.ReadAll(resp.Body)
			if !consumeError(&err) {
				return dumpError(err)
			}
		}
	}

	w.Header().Del("Content-Length")
	w.Header().Set("Content-Encoding", "gzip")
	w.WriteHeader(resp.StatusCode)

	if len(body) <= 0 {
		return
	}

	var (
		rules           []ReRule
		bodyExtraHeader string
	)

	switch p {
	case HD_html:
		rules = reRules.Html
	case HD_javascript:
		rules = reRules.Js
	case HD_json:
		rules = reRules.Json
	case HD_css:
		rules = reRules.Css
	}

	if log.V(5) {
		log.Infof("Original entity %s\n%s", reqPath, string(body))
	}

	if s.abusing {
		imgSrc := fmt.Sprintf(`<img src="/!%s/sorry`, reqHost)
		body = bytes.Replace(body, []byte(`<img src="/sorry`), []byte(imgSrc), 1)
		rules = nil
	}

	for i, r := range rules {
		if r.PathRe != nil && r.PathRe.FindString(reqPath) == NULL {
			if log.V(4) {
				log.Infof("re.%d=[%s] pathRe=deny", i, r.ContentPattern.Pattern)
			}
			continue
		}
		if log.V(4) {
			log.Infof("re.%d=[%s] applied", i, r.ContentPattern.Pattern)
		}
		if r.Scheme&0xff > 0 {
			body = r.ContentRe.Replace(body, r.Replacement)
		}
		if r.Scheme&0xff00 > 0 {
			bodyExtraHeader += r.InsertHeader
		}
	}

	zw = gzip.NewWriter(w)
	if len(bodyExtraHeader) > 0 {
		zw.Write([]byte(bodyExtraHeader))
	}
	zw.Write(body)
	err = zw.Flush()
	return
}

func consumeError(ePtr *error) (ret bool) {
	var err = *ePtr
	if err == nil {
		return true
	}
	ret = err != io.EOF && err != http.ErrBodyReadAfterClose
	if ret {
		*ePtr = nil
	}
	return
}

func NewRequest(method string, u *url.URL, body io.Reader) (*http.Request, error) {
	rc, ok := body.(io.ReadCloser)
	if !ok && body != nil {
		rc = ioutil.NopCloser(body)
	}
	req := &http.Request{
		Method:     method,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       rc,
		Host:       u.Host,
	}
	if body != nil {
		switch v := body.(type) {
		case *bytes.Buffer:
			req.ContentLength = int64(v.Len())
		case *bytes.Reader:
			req.ContentLength = int64(v.Len())
		case *strings.Reader:
			req.ContentLength = int64(v.Len())
		}
	}

	return req, nil
}
