package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/GET", GETHandler)
	http.HandleFunc("/POST", POSTHandler)
	http.HandleFunc("/headers", HeadersHandler)
	http.HandleFunc("/host", HostHandler)
	http.HandleFunc("/cookie", CookieHandler)
	// starts a static file server. e.g. 127.0.0.1/static/sample.txt
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./fuzzer"))))
	log.Fatal(http.ListenAndServe(":80", nil))
}

func handler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	fmt.Fprintf(w, "Path: "+r.URL.Path)
}

func GETHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "GET parameters: %s=%s, %s=%s", "input0", r.URL.Query()["input0"][0], "input1", r.URL.Query()["input1"][0])
}

func POSTHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "POST parameters: %s=%s, %s=%s", "input2", r.PostFormValue("input2"), "input3", r.PostFormValue("input3"))
}

func HeadersHandler(w http.ResponseWriter, r *http.Request) {
	for name, values := range r.Header {
		// Loop over all values for the name.
		for _, value := range values {
			fmt.Fprintf(w, "%s: %s\r\n", name, value)
		}
	}
}

func HostHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Host header: "+r.Host)
}

func CookieHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("input4")
	if err != nil {
		log.Println(err)
	}

	fmt.Fprintf(w, "%s=%s\r\n", cookie.Name, cookie.Value)
}
