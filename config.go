package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"github.com/Lafeng/ezgoo/import/github.com/go-ini/ini"
	"github.com/Lafeng/ezgoo/import/github.com/tchap/go-patricia/patricia"
	"github.com/Lafeng/ezgoo/regexp"
	"io/ioutil"
	"strings"
	"sync/atomic"
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
	ForceTls          bool
	TrustProxy        bool
	Listen            string
	TlsCertificate    string
	TlsCertificateKey string
	PermitDomains     []string
	PermitClients     []string
}

func initAppConfig() (*AppConfig, error) {
	conf := new(AppConfig)
	err := ini.MapTo(conf, "config.ini")
	if err != nil {
		return nil, err
	}
	if len(conf.PermitDomains) > 0 {
		initDestChecker(conf.PermitDomains)
	}
	if listen != NULL {
		conf.Listen = listen
	}
	return conf, err
}

func reverseCharacters(src string) []byte {
	a := []byte(src)
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		a[j], a[i] = a[i], a[j]
	}
	return a
}

var (
	destChecker *patricia.Trie
)

func checkDestHost(host string) bool {
	if destChecker != nil {
		_, _, found, _ := destChecker.LongestMatch(reverseCharacters(host))
		return found
	}
	return true
}

func initDestChecker(keys []string) {
	destChecker = patricia.NewTrie()
	for _, k := range keys {
		if len(k) > 0 {
			destChecker.Set(reverseCharacters(k), true)
		}
	}
}
