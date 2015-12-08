package main

import (
	"fmt"
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
	conf, _ := initAppConfig()
	val := reflect.ValueOf(conf).Elem()
	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		fv := val.Field(i)
		ft := typ.Field(i)
		if fv.CanInterface() {
			t.Logf("%s = %v", ft.Name, fv.Interface())
		}
	}
	t.Log(conf.domainRestrictions)
	t.Log(conf.clientRestrictions)
}
