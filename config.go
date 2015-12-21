package main

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync/atomic"

	log "github.com/Lafeng/ezgoo/glog"
	"github.com/Lafeng/ezgoo/regexp"
	"github.com/armon/go-radix"
	"github.com/go-ini/ini"
	"github.com/spance/ipatrie"
)

type RegexpDescr struct {
	Flags   string `xml:"flags,attr"`
	Pattern string `xml:",chardata"`
}

type ReRule struct {
	XMLName         xml.Name `xml:"ReRule"`
	PathPattern     *RegexpDescr
	ContentPattern  *RegexpDescr
	Replacement     []byte
	InsertHeader    string
	InsertHeaderBak string
	SchemeExpr      string
	Scheme          uint32
	PathRe          *RegexpHelper
	ContentRe       *RegexpHelper
}

type RegexpHelper struct {
	*regexp.Regexp
	counter uint32
	flag_g  bool
}

type ReRules struct {
	Version string
	XMLName xml.Name `xml:"ReRules"`
	Html    []ReRule `xml:"Html>ReRule"`
	Js      []ReRule `xml:"Js>ReRule"`
	Json    []ReRule `xml:"Json>ReRule"`
	Css     []ReRule `xml:"Css>ReRule"`
}

func (rd *RegexpDescr) initRegexpHelper() (*RegexpHelper, error) {
	if rd.Pattern == NULL {
		return nil, nil
	}
	var err error
	var r = new(RegexpHelper)
	rd.Pattern = strings.TrimSpace(rd.Pattern)
	r.Regexp, err = regexp.Compile(rd.Pattern)
	if err != nil {
		return nil, err
	}
	for _, flag := range rd.Flags {
		switch flag {
		case 'g':
			r.flag_g = true
		}
	}
	return r, nil
}

func (r *RegexpHelper) Replace(src, repl []byte) []byte {
	if r.flag_g {
		dst, n := r.ReplaceAll2(src, repl)
		atomic.AddUint32(&r.counter, uint32(n))
		return dst
	} else {
		return r.ReplaceOnce(src, repl)
	}
}

func (r *ReRules) String() string {
	var buf = new(bytes.Buffer)
	for j, rr := range []*[]ReRule{&r.Html, &r.Js, &r.Json} {
		var field string
		switch j {
		case 0:
			field = "html"
		case 1:
			field = "js"
		case 2:
			field = "json"
		}
		fmt.Fprintf(buf, field+"\n")
		for i, v := range *rr {
			fmt.Fprintf(buf, "%d    PathPattern: %v\n", i, v.PathPattern)
			fmt.Fprintf(buf, "%d ContentPattern: %v\n", i, v.ContentPattern)
			fmt.Fprintf(buf, "%d    Replacement: %v\n", i, v.Replacement)
			fmt.Fprintf(buf, "%d   InsertHeader: %v\n", i, v.InsertHeader)
		}
		fmt.Fprintln(buf)
	}
	return buf.String()
}

func initReRules() (*ReRules, error) {
	fd, err := ioutil.ReadFile("rules.xml")
	if err != nil {
		return nil, err
	}
	var rules ReRules
	err = xml.Unmarshal(fd, &rules)
	if err == nil {
		err = initRegexp(&rules)
	}
	return &rules, err
}

func initRegexp(r *ReRules) (err error) {
	//dynRu := regexp.MustCompile(`\{(\w+)\}`)
	for _, rr := range [][]ReRule{r.Html, r.Js, r.Json, r.Css} {
		for j, _ := range rr {
			ru := &rr[j]
			if ru.PathPattern != nil {
				ru.PathRe, err = ru.PathPattern.initRegexpHelper()
				if err != nil {
					return
				}
			}
			if ru.ContentPattern != nil {
				ru.ContentRe, err = ru.ContentPattern.initRegexpHelper()
				if err != nil {
					return
				}
			}

			if ru.SchemeExpr == NULL {
				ru.SchemeExpr = "replace=all"
			}

			ru.Scheme = parseScheme(ru.SchemeExpr)

			if ru.InsertHeader != NULL {
				ru.InsertHeader = strings.TrimSpace(ru.InsertHeader)
			}
		}
	}
	return
}

// 0xFF ff FF ff
//            ++ replace
//         ++    insert
func parseScheme(expr string) uint32 {
	var flags = []uint32{0, 0, 0, 0}
	re1 := regexp.MustCompile("\\s+")
	lines := re1.Split(strings.TrimSpace(expr), -1)
	for _, line := range lines {
		tokens := strings.Split(line, "=")
		if len(tokens) == 2 {
			var bits *uint32
			var token = strings.TrimSpace(tokens[0])
			switch token {
			case "replace":
				bits = &flags[0]
			case "insert":
				bits = &flags[1]
			default:
				panic("unknown " + token)
			}
			token = strings.TrimSpace(tokens[1])
			switch token {
			case "all":
				*bits = 0xff
			case "modern":
				*bits = 0xf
			case "outdate":
				*bits = 0x1
			default:
				panic("unknown " + token)
			}
		}
	}
	return flags[0] | flags[1]<<8 | flags[2]<<16 | flags[3]<<24
}

type AppConfig struct {
	ForceHttps         bool
	TrustProxy         bool
	servers            []*AppServ
	domainRestrictions DomainRestriction
	clientRestrictions ClientRestriction
	destChecker        *radix.Tree
	ipaTrie            *ipatrie.Trie
}

type DomainRestriction struct {
	Suffixes []string
	count    int
}

type ClientRestriction struct {
	AcceptLanguage string
	UserAgent      string
	Addresses      []string
	prefixCount    int
}

type AppServ struct {
	tlType            TLType
	cert              *tls.Certificate
	Listen            string
	TlsCertificate    string
	TlsCertificateKey string
}

type TLType int

const (
	TL_PLAIN TLType = iota
	TL_TLS
)

func initAppConfig() (*AppConfig, error) {
	cfg, err := ini.Load("config.ini")
	if err != nil {
		return nil, err
	}
	var conf = new(AppConfig)
	err = cfg.Section("Basic").MapTo(conf)
	if err != nil {
		return nil, err
	}
	err = cfg.Section("DomainRestriction").MapTo(&conf.domainRestrictions)
	if err != nil {
		return nil, err
	}
	err = cfg.Section("ClientRestriction").MapTo(&conf.clientRestrictions)
	if err != nil {
		return nil, err
	}
	var servs = make([]*AppServ, 2)
	for i, label := range []string{"0HTTP.Server", "1HTTPS.Server"} {
		var serv = new(AppServ)
		servs[i] = serv
		serv.tlType = TLType(int(label[0]) - 0x30)
		err = cfg.Section(label[1:]).MapTo(serv)
		if err != nil {
			return nil, err
		}
	}
	err = conf.verifyServerConfig(servs)
	if err != nil {
		return nil, err
	}
	// init restrictions
	conf.initDomainRestriction()
	conf.initClientRestriction()
	conf.PrintInfo()
	return conf, err
}

func reverseCharacters(src string) string {
	a := []byte(src)
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		a[j], a[i] = a[i], a[j]
	}
	return string(a)
}

func (c *AppConfig) initDomainRestriction() {
	keys := c.domainRestrictions.Suffixes
	if len(keys) <= 0 {
		return
	}
	c.destChecker = radix.New()
	for _, k := range keys {
		if len(k) > 0 {
			c.destChecker.Insert(reverseCharacters(k), true)
		}
	}
	c.destChecker.Walk(func(string, interface{}) bool {
		c.domainRestrictions.count++
		return false
	})
}

func (c *AppConfig) CheckDomainRestriction(host string) bool {
	if c.destChecker != nil {
		_, _, found := c.destChecker.LongestPrefix(reverseCharacters(host))
		return found
	}
	return true
}

func (c *AppConfig) initClientRestriction() {
	prefix := c.clientRestrictions.Addresses
	if len(prefix) <= 0 {
		return
	}
	c.ipaTrie = ipatrie.NewTrie()
	for _, p := range prefix {
		a, m, e := ipatrie.ParseCIDR(p)
		if e == nil {
			c.ipaTrie.Insert(a, m)
		} else {
			log.Warningf("Parse cidr=%s error=%v", p, e)
		}
	}
	c.clientRestrictions.prefixCount = c.ipaTrie.Size()
}

func (c *AppConfig) CheckClientRestriction(s *Session, r *http.Request) bool {
	res := c.clientRestrictions
	if len(res.AcceptLanguage) > 0 && !strings.Contains(r.Header.Get("Accept-Language"), res.AcceptLanguage) {
		return false
	}

	if len(res.UserAgent) > 0 && !strings.Contains(r.UserAgent(), res.UserAgent) {
		return false
	}

	if c.ipaTrie != nil {
		remoteAddr := ipatrie.ParseIPv4(s.aAddr)
		// ipv6 passed
		if remoteAddr > 0 && !c.ipaTrie.Match(remoteAddr) {
			return false
		}
	}
	return true
}

func (c *AppConfig) verifyServerConfig(_servs []*AppServ) error {
	var servs = make([]*AppServ, 0, 2)
	for _, s := range _servs {
		switch s.tlType {
		case TL_PLAIN: // http
			if len(s.Listen) > 0 {
				servs = append(servs, s)
			}
		case TL_TLS: // https
			if len(s.Listen) > 0 {
				servs = append(servs, s)
			} else {
				continue
			}
			cert, err := tls.LoadX509KeyPair(s.TlsCertificate, s.TlsCertificateKey)
			if err == nil {
				s.cert = &cert
			} else {
				return err
			}
		}
	}
	if len(servs) < 1 {
		return fmt.Errorf("both http.server and https.server were not specified")
	}
	c.servers = servs
	return nil
}

func (c *AppConfig) PrintInfo() {
	d, r := c.domainRestrictions, c.clientRestrictions
	log.Infof("DomainRestriction count=%d\n", d.count)
	log.Infof("ClientRestriction AL=[%s] UA=[%s] CIDR=%d\n", r.AcceptLanguage, r.UserAgent, r.prefixCount)
}
