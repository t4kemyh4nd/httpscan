package fuzzer

import(
	"fmt"
	"strings"
)

// Gets valid characters after the file path
func ValidCharsAfterPath(URL string, path string) []string{
	fmt.Println("Checking for valid characters after file path...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "GET"
	r.HttpVersion = "1.1"
	r.Method = "GET"
	r.Headers = []string{}
	allowedChars := []string{}
	payloads := GenerateURLEncodedPayloads()
	defer fmt.Println("Done...")
	for i:=0;i<len(payloads);i++{
		r.Path = "/" + path + payloads[i]
		sc, res := r.MakeRequest()
		if sc=="200" && strings.Contains(res,"Test file"){
			allowedChars = append(allowedChars, payloads[i])
		}
	}
	return allowedChars
}

// Gets valid characters between slashes encoded payloads
func IgnoredCharsBetweenSlashesEncoded(URL string, path string) []string{
	fmt.Println("Checking for allowed encoded characters between slashes...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "GET"
	r.HttpVersion = "1.1"
	r.Method = "GET"
	r.Headers = []string{}
	allowedChars := []string{}
	payloads := GenerateURLEncodedPayloads()
	split := strings.Split(path,"/")
	defer fmt.Println("Done...")
	for i:=0;i<len(payloads);i++{
		r.Path = "/" + split[0] + "/%" + payloads[i] + "/" + split[1]
		sc, res := r.MakeRequest()
		if sc=="200" && strings.Contains(res,"Test file"){
			allowedChars = append(allowedChars, payloads[i])
		}
	}
	return allowedChars
}

// Gets valid characters between slashes
func IgnoredCharsBetweenSlashes(URL string, path string) []string{
	fmt.Println("Checking for allowed characters between slashes...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "GET"
	r.HttpVersion = "1.1"
	r.Method = "GET"
	r.Headers = []string{}
	allowedChars := []string{}
	split := strings.Split(path,"/")
	defer fmt.Println("Done...")
	for i:=0;i<256;i++{
		r.Path = "/" + split[0] + "/" + string(i) + "/" + split[1]
		sc, res := r.MakeRequest()
		if sc=="200" {
			if strings.Contains(res,"Test") {
				allowedChars = append(allowedChars, string(i))
			}
		}
	}
	return allowedChars
}

// Checks if the path can start with values other than /
func StartPathWith(URL string, path string) []string{
	fmt.Println("Starting path with different payloads...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "GET"
	r.HttpVersion = "1.1"
	r.Method = "GET"
	r.Headers = []string{}
	startsWith := []string{"%%2F","/%%2F/","/%%2E/"}
	allowed := []string{}
	defer fmt.Println("Done...")
	for i:=0;i<len(startsWith);i++{
		r.Path = startsWith[i] + path
		sc, res := r.MakeRequest()
		if sc=="200"{  
			if strings.Contains(res,"Test file"){
				allowed = append(allowed, startsWith[i])
			}
		}
	}
	return allowed
}

// Checks if characters in file name can be URL encoded
func URLEncodedFileChar(URL string) bool{
	fmt.Println("URL encoding a single character in the file name...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "GET"
	r.HttpVersion = "1.1"
	r.Path = "/static/%%73ample.txt"
	defer fmt.Println("Done...")
	sc, res := r.MakeRequest()
	if sc=="200" && strings.Contains(res,"Test file"){
		return true
	}
	return false
}

// Checks if the dot can be replaced with %u022e can be updates to with other URL encoded values
func ReplaceDotInExtension(URL string, path string) bool{
fmt.Println("URL encoding the dot in file extension...")
	r := TCPeditor{}
	r.Server = URL
	r.Host = URL
	r.Method = "GET"
	r.HttpVersion = "1.1"
	r.Method = "GET"
	r.Headers = []string{}
	splitResult := strings.Split(path,"/")
	fileName := splitResult[len(splitResult)-1]
	fileName = strings.Replace(fileName,".","%%u022e",1)
	r.Path = "/" + splitResult[0] + "/" + fileName
	defer fmt.Println("Done...")
	sc, res := r.MakeRequest()
	if sc=="200" && strings.Contains(res,"Test file"){
		return true
	}
	return false
}
