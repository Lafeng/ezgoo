package main

import (
	"fmt"
	"github.com/Lafeng/ezgoo/import/github.com/go-ini/ini"
	"os"
	"reflect"
	"testing"
)

func init() {
	os.Chdir("dist")
}

func TestRules(t *testing.T) {
	fmt.Println(initReRules())
}

func TestConfig(t *testing.T) {
	conf := new(AppConfig)
	err := ini.MapTo(conf, "config.ini")
	if err != nil {
		t.Error(err)
	}
	val := reflect.ValueOf(conf).Elem()
	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		fv := val.Field(i)
		ft := typ.Field(i)
		if fv.CanInterface() {
			t.Logf("%s = %v", ft.Name, fv.Interface())
		}
	}
}
