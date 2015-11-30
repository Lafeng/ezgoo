package main

import (
	"bytes"
	"fmt"
	log "github.com/Lafeng/ezgoo/glog"
	"net/http"
	"runtime"
	"strings"
)

func dumpHeader(label string, h http.Header) {
	var buf = new(bytes.Buffer)
	fmt.Fprintln(buf, "  "+label)
	for k, arr := range h {
		if len(arr) == 1 {
			fmt.Fprintf(buf, "     %s: %s\n", k, arr[0])
		} else {
			fmt.Fprintf(buf, "     %s: [%s]\n", k, strings.Join(arr, "],  ["))
		}
	}
	fmt.Print(buf.String())
}

func dumpStack() string {
	buf := new(bytes.Buffer)
	pcArr := make([]uintptr, 20)
	n := runtime.Callers(0, pcArr)

	for i := 2; i < n; i++ {
		pc := pcArr[i]
		fn := runtime.FuncForPC(pc)
		fmt.Fprintf(buf, "%s():0x%x\n", fn.Name(), fn.Entry())
		file, line := fn.FileLine(pc)
		fmt.Fprintf(buf, "\t%s:%d\n", file, line)
	}
	return buf.String()
}

func dumpError(v interface{}) error {
	if v != nil {
		var err error
		switch v.(type) {
		case error:
			err = v.(error)
		default:
			err = fmt.Errorf("%v", v)
		}
		log.Errorf("Error: %v\n%s", err, dumpStack())
		return err
	}
	return nil
}

const robots_response = `User-agent: *
Disallow: /
`

const debug_image_interceptor = `<head>
<script>
(function(){
	var _nativeImage=Image;
	Image=function(){
		Object.defineProperty(this, "src", {
			set: function(v) {
				console.error("interceptor.setter/src="+v);
				var img=new _nativeImage;
				img.src=v;
			}
		});
	}
})();
</script>
`
