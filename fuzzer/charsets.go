package fuzzer

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func EncodeWithPython(input, charset string) string {
	app := "python"

	arg0 := "fuzzer/encode.py"
	arg1 := input
	arg2 := charset

	cmd := exec.Command(app, arg0, arg1, arg2)
	stdout, _ := cmd.Output()

	return string(stdout)
}

func ValidCharsets(server, httpv string) []string {
	fmt.Println("Checking for valid charsets now...")
	charlist := "utf-16,IBM500,IBM437,IBM037,ASMO-708,DOS-720,ibm737,ibm775,ibm850,ibm852,IBM855,ibm857,IBM00858,IBM860,ibm861,DOS-862,IBM863,IBM864,IBM865,cp866,ibm869,IBM870,windows-874,cp875,shift_jis,gb2312,ks_c_5601-1987,big5,IBM1026,IBM01047,IBM01140,IBM01141,IBM01142,IBM01143,IBM01144,IBM01145,IBM01146,IBM01147,IBM01148,IBM01149,unicodeFFFE,windows-1250,windows-1251,Windows-1252,windows-1253,windows-1254,windows-1255,windows-1256,windows-1257,windows-1258,Johab,macintosh,x-mac-japanese,x-mac-chinesetrad,x-mac-korean,x-mac-arabic,x-mac-hebrew,x-mac-greek,x-mac-cyrillic,x-mac-chinesesimp,x-mac-romanian,x-mac-ukrainian,x-mac-thai,x-mac-ce,x-mac-icelandic,x-mac-turkish,x-mac-croatian,utf-32,utf-32BE,x-Chinese-CNS,x-cp20001,x-Chinese-Eten,x-cp20003,x-cp20004,x-cp20005,x-IA5,x-IA5-German,x-IA5-Swedish,x-IA5-Norwegian,us-ascii,x-cp20261,x-cp20269,IBM273,IBM277,IBM278,IBM280,IBM284,IBM285,IBM290,IBM297,IBM420,IBM423,IBM424,x-EBCDIC-KoreanExtended,IBM-Thai,koi8-r,IBM871,IBM880,IBM905,IBM00924,EUC-JP,x-cp20936,x-cp20949,cp1025,koi8-u,iso-8859-1,iso-8859-2,iso-8859-3,iso-8859-4,iso-8859-5,iso-8859-6,iso-8859-7,iso-8859-8,iso-8859-9,iso-8859-13,iso-8859-15,x-Europa,iso-8859-8-i,iso-2022-jp,csISO2022JP,iso-2022-jp,iso-2022-kr,x-cp50227,euc-jp,EUC-CN,euc-kr,hz-gb-2312,GB18030,x-iscii-de,x-iscii-be,x-iscii-ta,x-iscii-te,x-iscii-as,x-iscii-or,x-iscii-ka,x-iscii-ma,x-iscii-gu,x-iscii-pa,utf-7,utf-8"
	charsets := strings.Split(charlist, ",")

	r := TCPeditor{}

	results := []string{}

	r.Server = server
	r.Method = "POST"
	r.Path = "/POST"
	r.HttpVersion = httpv
	r.Host = server
	for _, charset := range charsets {
		fmt.Println("Checking charset " + charset + " now...")
		input := "input2=foo&input3=bar"
		rawbody := EncodeWithPython(input, charset)
		r.Body = strings.ReplaceAll(EncodeWithPython(input, charset), "%", "%%")
		r.Headers = []string{"Content-Length: " + strconv.Itoa(len(rawbody)-1), "Content-Type: application/x-www-form-urlencoded; charset=" + charset}
		sc, res := r.MakeRequest()

		//unknown charsets in encode.py return vanilla body so we check for "%" and see if input has been encoded
		if strings.Contains(r.Body, "%") && sc == "200" && strings.Contains(res, "foo") && strings.Contains(res, "bar") {
			results = append(results, charset)
		}
	}

	return results
}
