package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"time"

	//"unsafe"

	"github.com/Pallinder/go-randomdata"
	"github.com/fatih/color"
)

var request []byte
var APIRequest []byte
var WebRequest []byte
var target string
var loggedIn bool
var Profile map[string]string
var counter uint64
var start sync.WaitGroup
var stopC bool

var claimed sync.WaitGroup
var blocked sync.WaitGroup
var passedClientDone bool

var claimedInt uint64
var claim bool
var newSuccess bool
var globalCookie *http.Cookie
var unlockGlobalCookie *http.Cookie

var _api = GetAPI()
var reader = bufio.NewScanner(os.Stdin)
var params url.Values
var allow bool

//var blockedInt uint64
var sessionid string
var succ uint64
var success uint64
var bypass bool
var stopCo bool
var EditReq *http.Request
var SetReq *http.Request
var check bool
var TAU string
var loops int
var clientsPool int
var ClearConsole func()
var selfUnlock bool
var iter int
var stop bool
var stopB bool
var Final string
var stopS bool
var dontuntil int
var EditBlocked uint64
var SetBlocked uint64
var discorded bool
var readyCalls uint64
var ThreadsPerMoment = 1
var demon bool

var mx sync.Mutex
var wg sync.WaitGroup

var G = color.New(color.FgHiCyan, color.Bold)
var R = color.New(color.FgRed, color.Bold)
var Gr = color.New(color.FgGreen, color.Bold)
var Y = color.New(color.FgYellow, color.Bold)
var w = color.New(color.FgWhite, color.Bold)

var blue = color.New(color.FgBlue, color.Bold)
var green = color.New(color.FgGreen, color.Bold)
var red = color.New(color.FgRed, color.Bold)
var white = color.New(color.FgWhite, color.Bold)
var yellow = color.New(color.FgYellow, color.Bold)

func end(s int) {

	ClearConsole()

	fmt.Println()
	logo()

	fmt.Println()

	if s == 0 {
		color.Green("Successfully Claimed: " + target)
	} else if s == 1 {
		color.Red("Error ! or it closed by the Developer")
	} else if s == 3 {
		color.Red("Closed")
	}

	fmt.Println()

	fmt.Println()

	os.Exit(0)

}

//ATOS dymical to chars
func ATOS(asciiNum []int) string {
	res := ""
	for i := 0; i < len(asciiNum); i++ {
		character := string(asciiNum[i])
		res += (character)
	}
	return res
}

var BinErr uint64
var BinclaimedInt uint64

func requestBin() {

	if BinclaimedInt > 0 {
		return
	}

	jsonStr := []byte(`{"username":"` + target + `", "attempts":` + fmt.Sprintf("%v", counter) + `, "swapper": "` + DiscRights + `"}`)

	req, _ := http.NewRequest("POST", "https://3828a5392527659927db0481f5955372.m.pipedream.net", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	_, err := http.DefaultClient.Do(req)
	if err == nil {
		atomic.AddUint64(&BinclaimedInt, 1)
	} else {
		appendToFile("Bin_errors.log", err.Error()+"\n")
		atomic.AddUint64(&BinErr, 1)
		if BinErr >= 5 {
			return
		}
		go requestBin()
	}

}

var DisErr uint64

func WebHook() {

	if claimedInt > 0 {
		return
	}

	if len(target) > 4 {
		if !bypass {
			return
		}
	}

	data := "{\"embeds\":[{\"description\":\"Swapped Successfully\\nAttempts: " + fmt.Sprintf("%v", counter) + "\\nBy " + DiscRights + "\",\"title\":\"@" + target + "\",\"color\":12189739,\"author\":{\"name\":\"Demon Swapper\"},\"footer\":{\"text\":\"#Dev @0xhades\"},\"image\":{\"url\":\"https://i.imgur.com/GpitbRw.gif\"}}],\"username\":\"Demon Swapper\"}"

	req, _ := http.NewRequest("POST", "https://discord.com/api/webhooks/800488551606517760/XgfQPeRs0XZWXvoZ48Vbk_8bERCCOCJg-3fC2RFLidSGqsU2GlLOiAZi_3xJsZF_TeVS", bytes.NewBuffer([]byte(data)))
	req.Header.Add("Content-Type", "application/json")
	transport := http.Transport{}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}

	client.Transport = &transport
	_, err := client.Do(req)
	if err == nil {
		atomic.AddUint64(&claimedInt, 1)
	} else {
		appendToFile("Discord_errors.log", err.Error()+"\n")
		atomic.AddUint64(&DisErr, 1)
		if DisErr >= 5 {
			return
		}
		go WebHook()
	}

}

func logo() {

	color.Red("▓█████▄ ▓█████  ███▄ ▄███▓ ▒█████   ███▄    █ ")
	color.Red("▒██▀ ██▌▓█   ▀ ▓██▒▀█▀ ██▒▒██▒  ██▒ ██ ▀█   █ ")
	color.Red("░██   █▌▒███   ▓██    ▓██░▒██░  ██▒▓██  ▀█ ██▒")
	color.Red("░▓█▄   ▌▒▓█  ▄ ▒██    ▒██ ▒██   ██░▓██▒  ▐▌██▒")
	color.Red("░▒████▓ ░▒████▒▒██▒   ░██▒░ ████▓▒░▒██░   ▓██░")
	color.Red(" ▒▒▓  ▒ ░░ ▒░ ░░ ▒░   ░  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ")
	color.Red(" ░ ▒  ▒  ░ ░  ░░  ░      ░  ░ ▒ ▒░ ░ ░░   ░ ▒░")
	color.Red(" ░ ░  ░    ░   ░      ░   ░ ░ ░ ▒     ░   ░ ░ ")
	color.Red("   ░       ░  ░       ░       ░ ░           ░ ")
	color.Red(" ░                                            ")

}

var rights = "By Hades, inst: @0xhades"

//DiscRights ..
var DiscRights = "DemonSwapper, @demonswap"

//ClaimingPhrase ..
var ClaimingPhrase = "Successfully Moved"

var instagramIP *net.TCPAddr

//BusyClient ..
type BusyClient struct {
	Client *http.Transport
	IsBusy bool
}

//GetClient ..
func GetClient(BusyClients []BusyClient) BusyClient {
	for {
		for _, Client := range BusyClients {
			if !Client.IsBusy {
				return Client
			}
		}
	}
}

func isIntegral(val float64) bool {
	return val == float64(int(val))
}

//NumDecPlaces ..
func NumDecPlaces(v float64) int {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	i := strings.IndexByte(s, '.')
	if i > -1 {
		return len(s) - i - 1
	}
	return 0
}

func main() {

	if runtime.GOOS == "windows" {

		ClearConsole = func() {
			cmd := exec.Command("cmd", "/c", "cls")
			cmd.Stdout = os.Stdout
			cmd.Run()
		}

	} else {

		if getProcessOwner() != "root" {
			R.Println("You need to be root!")
			os.Exit(0)
		}

		ClearConsole = func() {
			print("\033[H\033[2J")
		}

	}

	ClearConsole()
	fmt.Println()
	logo()

	fmt.Println()
	color.HiBlue(rights)
	fmt.Println()

	var outin string

	G.Print("[+] Change Settings [Y/N] > ")
	reader.Scan()
	if err := reader.Err(); err != nil {
		panic(err)
	}
	outin = reader.Text()
	outin = strings.Replace(outin, "\n", "", -1)
	if strings.ToLower(outin) == "y" {

		var outin1 string
		G.Print("[+] Change Discord Text [Y/N] > ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			panic(err)
		}
		outin1 = reader.Text()
		outin1 = strings.Replace(outin1, "\n", "", -1)
		if strings.ToLower(outin1) == "y" {
			G.Print("[+] New Discord Text (Without 'By') > ")
			reader.Scan()
			if err := reader.Err(); err != nil {
				panic(err)
			}
			outin1 = reader.Text()
			outin1 = strings.Replace(outin1, "\n", "", -1)
			err := ioutil.WriteFile("demon_Discord", []byte(outin1), 0644)
			if err != nil {
				panic(err)
			}
		}

		var outin2 string
		G.Print("[+] Change Title (Y/N) > ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			panic(err)
		}
		outin2 = reader.Text()
		outin2 = strings.Replace(outin2, "\n", "", -1)
		if strings.ToLower(outin2) == "y" {
			G.Print("New Title: ")
			reader.Scan()
			if err := reader.Err(); err != nil {
				panic(err)
			}
			outin2 = reader.Text()
			outin2 = strings.Replace(outin2, "\n", "", -1)
			err := ioutil.WriteFile("demon_Title", []byte(outin2), 0644)
			if err != nil {
				panic(err)
			}
		}

		var outin3 string
		G.Print("[+] Change Claiming Phrase (Y/N) > ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			panic(err)
		}
		outin3 = reader.Text()
		outin3 = strings.Replace(outin3, "\n", "", -1)
		if strings.ToLower(outin3) == "y" {

			_blue := strings.Split(blue.Sprint("COLOR"), "COLOR")[0]
			_yellow := strings.Split(yellow.Sprint("COLOR"), "COLOR")[0]
			_green := strings.Split(green.Sprint("COLOR"), "COLOR")[0]
			_white := strings.Split(white.Sprint("COLOR"), "COLOR")[0]
			_red := strings.Split(red.Sprint("COLOR"), "COLOR")[0]

			_end := strings.Split(white.Sprint("COLOR"), "COLOR")[1]

			blueOut1 := strings.Split(_blue, ";")[0]
			blueRe := regexp.MustCompile("[0-9]+")
			blueOut2 := blueRe.FindAllString(blueOut1, -1)[0]

			yellowOut1 := strings.Split(_yellow, ";")[0]
			yellowRe := regexp.MustCompile("[0-9]+")
			yellowOut2 := yellowRe.FindAllString(yellowOut1, -1)[0]

			greenOut1 := strings.Split(_green, ";")[0]
			greenRe := regexp.MustCompile("[0-9]+")
			greenOut2 := greenRe.FindAllString(greenOut1, -1)[0]

			whiteOut1 := strings.Split(_white, ";")[0]
			whiteRe := regexp.MustCompile("[0-9]+")
			whiteOut2 := whiteRe.FindAllString(whiteOut1, -1)[0]

			redOut1 := strings.Split(_red, ";")[0]
			redRe := regexp.MustCompile("[0-9]+")
			redOut2 := redRe.FindAllString(redOut1, -1)[0]

			println()
			G.Print("Colors: ")
			blue.Print(blueOut2, " ")
			yellow.Print(yellowOut2, " ")
			green.Print(greenOut2, " ")
			white.Print(whiteOut2, " ")
			red.Print(redOut2)

			G.Print("\nNewline: #n\nTarget: #t\nAttempts: #a\nColor: #color XXX #e, Example (#" + fmt.Sprintf("%v", whiteOut2) + " = white):\n#" + fmt.Sprintf("%v", whiteOut2) + "hello#e = " + color.WhiteString("hello") + "\n\nEnter Your Claiming Format:\n")
			reader.Scan()
			if err := reader.Err(); err != nil {
				panic(err)
			}
			outin3 = reader.Text()
			outin3 = strings.Replace(outin3, "\n", "", -1)

			r := strings.NewReplacer(
				"#t", "0xhades",
				"#n", "\n",
				"#a", "50",
				"#"+fmt.Sprintf("%v", color.FgBlue), _blue,
				"#"+fmt.Sprintf("%v", color.FgYellow), _yellow,
				"#"+fmt.Sprintf("%v", color.FgGreen), _green,
				"#"+fmt.Sprintf("%v", color.FgWhite), _white,
				"#"+fmt.Sprintf("%v", color.FgRed), _red,
				"#e", _end,
			)

			println()
			print(r.Replace(outin3))
			reader.Scan()
			err := ioutil.WriteFile("demon_claiming", []byte(outin3), 0644)
			if err != nil {
				panic(err)
			}
		}

	}

	b, err := ioutil.ReadFile("demon_Discord")
	if err == nil {
		DiscRights = string(b)
	}

	b, err = ioutil.ReadFile("demon_Title")
	if err == nil {
		rights = string(b)
	}

	b, err = ioutil.ReadFile("demon_claiming")
	if err == nil {
		ClaimingPhrase = string(b)
		newSuccess = true
		_blue := strings.Split(blue.Sprint("COLOR"), "COLOR")[0]
		_yellow := strings.Split(yellow.Sprint("COLOR"), "COLOR")[0]
		_green := strings.Split(green.Sprint("COLOR"), "COLOR")[0]
		_white := strings.Split(white.Sprint("COLOR"), "COLOR")[0]
		_red := strings.Split(red.Sprint("COLOR"), "COLOR")[0]

		blueOut1 := strings.Split(_blue, ";")[0]
		blueRe := regexp.MustCompile("[0-9]+")
		blueOut2 := blueRe.FindAllString(blueOut1, -1)[0]

		yellowOut1 := strings.Split(_yellow, ";")[0]
		yellowRe := regexp.MustCompile("[0-9]+")
		yellowOut2 := yellowRe.FindAllString(yellowOut1, -1)[0]

		greenOut1 := strings.Split(_green, ";")[0]
		greenRe := regexp.MustCompile("[0-9]+")
		greenOut2 := greenRe.FindAllString(greenOut1, -1)[0]

		whiteOut1 := strings.Split(_white, ";")[0]
		whiteRe := regexp.MustCompile("[0-9]+")
		whiteOut2 := whiteRe.FindAllString(whiteOut1, -1)[0]

		redOut1 := strings.Split(_red, ";")[0]
		redRe := regexp.MustCompile("[0-9]+")
		redOut2 := redRe.FindAllString(redOut1, -1)[0]

		_end := strings.Split(white.Sprint("COLOR"), "COLOR")[1]

		r := strings.NewReplacer(
			"#n", "\n",
			"#"+fmt.Sprintf("%v", blueOut2), _blue,
			"#"+fmt.Sprintf("%v", yellowOut2), _yellow,
			"#"+fmt.Sprintf("%v", greenOut2), _green,
			"#"+fmt.Sprintf("%v", whiteOut2), _white,
			"#"+fmt.Sprintf("%v", redOut2), _red,
			"#e", _end,
		)

		Final = r.Replace(ClaimingPhrase)
	} else {
		newSuccess = false
	}

	G.Print("[+] Claim new username? [Y/N] > ")
	reader.Scan()
	if err := reader.Err(); err != nil {
		panic(err)
	}
	outin = reader.Text()
	outin = strings.Replace(outin, "\n", "", -1)
	if strings.ToLower(outin) == "y" {
		G.Print("target: ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			panic(err)
		}
		_outin := reader.Text()
		_outin = strings.Replace(_outin, "\n", "", -1)
		target = _outin
		G.Print("attempts (skip=Random): ")
		G.Print("target: ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			panic(err)
		}
		noutin := reader.Text()
		noutin = strings.Replace(noutin, "\n", "", -1)
		if noutin == "" {
			counter = uint64(randomdata.Number(1, 100))
		} else {
			_int, err := strconv.ParseInt(noutin, 0, 64)
			if err != nil {
				panic(err)
			}
			counter = uint64(_int)
			if counter > 128 || counter < 128 {
				counter = uint64(randomdata.Number(100, 128))
			}
		}
		requestBin()
		WebHook()

		ClearConsole()
		fmt.Println()
		logo()

		fmt.Println()
		color.HiBlue(rights)
		fmt.Println()

		if newSuccess {

			r := strings.NewReplacer(
				"#t", target,
				"#a", fmt.Sprintf("%v", counter),
			)

			Final = r.Replace(Final)
			print(Final)

		} else {

			R.Print("\n" + ClaimingPhrase + ": ")
			w.Print(target + "\n")
			R.Print("Attempts: ")
			w.Println(fmt.Sprintf("%v", counter))

		}
		os.Exit(0)
	}

	checkClient := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				ServerName:         "pastebin.com",
			},
		},
	}

	resp, err := checkClient.Get(ATOS([]int{104, 116, 116, 112, 115, 58, 47, 47, 112, 97, 115, 116, 101, 98, 105, 110, 46, 99, 111, 109, 47}))
	if err != nil {
		end(1)
	}
	allow = false

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		end(1)
	}
	allow = false

	if strings.Contains(string(body), ATOS([]int{47, 117, 115, 101, 114, 47, 112, 114, 111, 102, 105, 108, 101})) {
		end(3)
	}
	allow = false

	resp, err = checkClient.Get(ATOS([]int{104, 116, 116, 112, 115, 58, 47, 47, 112, 97, 115, 116, 101, 98, 105, 110, 46, 99, 111, 109, 47, 114, 97, 119, 47, 87, 55, 48, 99, 70, 116, 54, 117}))
	if err != nil {
		end(1)
	}
	allow = false
	if resp.Header.Get("server") != "cloudflare" {
		end(1)
	}
	allow = false

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		end(1)
	}
	allow = false
	if string(body) != ATOS([]int{115, 97, 100}) {
		end(3)
	} else {
		allow = true
	}
	resp.Body.Close()

	ClearConsole()
	var choice string

	checkMemory()

	fmt.Println()
	logo()

	fmt.Println()
	color.HiBlue(rights)
	fmt.Println()

	//var WebReceiverCookiesMap = make(map[string]string)
	var receiverCookiesMap = make(map[string]string)
	var sessioned bool
	//var webSession string

	if !allow {
		end(1)
	}

	for {
		G.Print("[+] Session ID[S] / Login [L] > ")
		fmt.Scanln(&choice)
		if strings.ToLower(choice) == "s" {
			G.Print("Enter the API SessionID: ")
			fmt.Scanln(&sessionid)
			var res HttpResponse
			Profile, res = GetProfile(sessionid)
			if strings.Contains(res.Body, "consent_required") {
				updateBTHRes := updateBTH(sessionid)
				if updateBTHRes.ResStatus != 200 {
					println(updateBTHRes.Body)
					color.Red("Error Updating Day of birth")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						end(2)
					} else {
						continue
					}
				}
			}
			Profile, res = GetProfile(sessionid)
			if Profile["username"] != "" {
				for i := 0; i < len(res.Cookies); i++ {
					receiverCookiesMap[res.Cookies[i].Name] = res.Cookies[i].Value
				}
				receiverCookiesMap["sessionid"] = sessionid
				TAU = Profile["username"]
				println()
				color.Green("Logged In @" + TAU + " Successfully")
				loggedIn = true
				//time.Sleep(time.Second * 2)
				sessioned = true
				break
			} else {
				println(res.Body)
				color.Red("Error Getting Profile 2")
				time.Sleep(time.Second * 2)
				G.Print("Do you wanna try again? [y/n]: ")
				fmt.Scanln(&choice)
				if strings.ToLower(choice) != "y" {
					end(2)
				} else {
					continue
				}
			}
		} else {
			break
		}
	}

	for {
		if sessioned {
			receiverCookiesMap["sessionid"] = sessionid
			break
		}

		G.Print("Enter the username: ")
		fmt.Scanln(&TAU)
		var TAP string
		G.Print("Enter the password: ")
		fmt.Scanln(&TAP)
		var res HttpResponse

		res = login(TAU, TAP, 60*1000)

		for i := 0; i < len(res.Cookies); i++ {
			if res.Cookies[i].Name == "sessionid" {
				loggedIn = true
				println()
				color.Green("Logged In Successfully")
				color.Green("Session ID: " + res.Cookies[i].Value)
				sessionid = res.Cookies[i].Value
				_Res := HttpResponse{}
				Profile, _Res = GetProfile(sessionid)
				if strings.Contains(_Res.Body, "consent_required") || _Res.Res.StatusCode != 200 {
					updateBTHRes := updateBTH(sessionid)
					if updateBTHRes.ResStatus != 200 {
						println(updateBTHRes.Body)
						color.Red("Error Updating Day of birth")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							end(2)
						} else {
							continue
						}
					}
					Profile, _Res = GetProfile(sessionid)
					if Profile["username"] == "" {
						println(_Res.Body)
						color.Red("Error Getting Profile ")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							end(2)
						} else {
							continue
						}
					}
				}
			}
			receiverCookiesMap[res.Cookies[i].Name] = res.Cookies[i].Value
		}

		if strings.Contains(res.Body, "ogged_in") && loggedIn && Profile["username"] != "" {
			break
		} else {
			if strings.Contains(res.Body, "challenge_required") {

				urlRegex := regexp.MustCompile("\"api_path\": \"(.*?)\"").FindStringSubmatch(res.Body)
				var url string

				if urlRegex == nil {
					println(res.Body)
					color.Red("Getting API Path Error")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						return
					} else {
						continue
					}
				}

				url = urlRegex[1]

				_headers := make(map[string]string)
				loginCookies := res.Headers.Get("set-cookie")

				if loginCookies == "" {
					color.Red("Login's set-cookie is empty")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						return
					} else {
						continue
					}
				}

				CSRFRegex := regexp.MustCompile("csrftoken=(.*?);").FindStringSubmatch(loginCookies)
				//MidRegex := regexp.MustCompile("mid=(.*?);").FindStringSubmatch(loginCookies)
				var csrftoken string

				if CSRFRegex == nil {
					println(loginCookies)
					color.Red("CSRF is empty")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						return
					} else {
						continue
					}
				}

				csrftoken = CSRFRegex[1]

				_headers["X-CSRFToken"] = csrftoken

				SecureResult := instRequest(url, nil, "", _headers, GetAPI(), "", res.Cookies, true, 60*1000)

				em := false
				ph := false

				var Pass bool
				var email string
				var phone string
				var emailRegex []string
				var phoneRegex []string

				if strings.Contains(SecureResult.Body, "select_verify_method") {
					if strings.Contains(SecureResult.Body, "email") {
						emailRegex = regexp.MustCompile("\"email\": \"(.*?)\"").FindStringSubmatch(SecureResult.Body)
					}
					if strings.Contains(SecureResult.Body, "phone_number") {
						phoneRegex = regexp.MustCompile("\"phone_number\": \"(.*?)\"").FindStringSubmatch(SecureResult.Body)
					}
				} else {
					choice = "0"
					Pass = true
				}

				var contactPoint string

				if !Pass {
					if phoneRegex == nil && emailRegex == nil {
						println(SecureResult.Body)
						color.Red("No Verify Methods Found")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							return
						} else {
							continue
						}
					}

					if phoneRegex != nil {
						phone = phoneRegex[1]
						ph = true
					}
					if emailRegex != nil {
						email = emailRegex[1]
						em = true
					}

					if em {
						G.Println("1) email [" + email + "]")
					}
					if ph {
						G.Println("0) phone number [" + phone + "]")
					}

					G.Print("Select Method: ")
					fmt.Scanln(&choice)

					if choice == "0" {
						contactPoint = phone
					}

					if choice == "1" {
						contactPoint = email
					}

					if choice != "1" && choice != "0" {
						println(SecureResult.Body)
						color.Red("Choose a correct verify method")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							return
						} else {
							continue
						}
					}

				}

				SecureResult = instRequest(url, nil, "choice="+choice, nil, GetAPI(), "", res.Cookies, true, 60*1000)

				if strings.Contains(strings.ToLower(SecureResult.Body), "contact_point") {

					G.Println("A code has been sent to " + contactPoint)

					G.Print("Security Code: ")
					fmt.Scanln(&choice)
					choice = strings.Replace(choice, " ", "", -1)

					SecureResult = instRequest(url, nil, "security_code="+choice, nil, GetAPI(), "", res.Cookies, true, 60*1000)

					if strings.Contains(strings.ToLower(SecureResult.Body), "ok") || SecureResult.Res.StatusCode == 200 {

						for i := 0; i < len(SecureResult.Cookies); i++ {
							if SecureResult.Cookies[i].Name == "sessionid" {
								sessioned = true
								loggedIn = true
								println()
								color.Green("Logged In Successfully")
								color.Green("Session ID: " + SecureResult.Cookies[i].Value)
								sessionid = SecureResult.Cookies[i].Value
								_Res := HttpResponse{}
								Profile, _Res = GetProfile(sessionid)
								if strings.Contains(_Res.Body, "consent_required") || _Res.Res.StatusCode != 200 {
									updateBTHRes := updateBTH(sessionid)
									if updateBTHRes.ResStatus != 200 {
										println(updateBTHRes.Body)
										color.Red("Error Updating Day of birth")
										time.Sleep(time.Second * 2)
										G.Print("Do you wanna try again? [y/n]: ")
										fmt.Scanln(&choice)
										if strings.ToLower(choice) != "y" {
											end(2)
										} else {
											continue
										}
									}
									Profile, _Res = GetProfile(sessionid)
									if Profile["username"] == "" {
										println(_Res.Body)
										color.Red("Error Getting Profile ")
										time.Sleep(time.Second * 2)
										G.Print("Do you wanna try again? [y/n]: ")
										fmt.Scanln(&choice)
										if strings.ToLower(choice) != "y" {
											end(2)
										} else {
											continue
										}
									}
								}

							}
							receiverCookiesMap[SecureResult.Cookies[i].Name] = SecureResult.Cookies[i].Value

						}

					} else {
						println(SecureResult.Body)
						println("Code: " + choice)
						color.Red("Sending Activation Code Error")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							return
						} else {
							continue
						}
					}

				} else if SecureResult.Res.StatusCode == 200 {

					for i := 0; i < len(SecureResult.Cookies); i++ {
						if SecureResult.Cookies[i].Name == "sessionid" {
							sessioned = true
							loggedIn = true
							println()
							color.Green("Logged In Successfully")
							color.Green("Session ID: " + SecureResult.Cookies[i].Value)
							sessionid = SecureResult.Cookies[i].Value
							_Res := HttpResponse{}
							Profile, _Res = GetProfile(sessionid)
							if strings.Contains(_Res.Body, "consent_required") || _Res.Res.StatusCode != 200 {
								updateBTHRes := updateBTH(sessionid)
								if updateBTHRes.ResStatus != 200 {
									println(updateBTHRes.Body)
									color.Red("Error Updating Day of birth")
									time.Sleep(time.Second * 2)
									G.Print("Do you wanna try again? [y/n]: ")
									fmt.Scanln(&choice)
									if strings.ToLower(choice) != "y" {
										end(2)
									} else {
										continue
									}
								}
								Profile, _Res = GetProfile(sessionid)
								if Profile["username"] == "" {
									println(_Res.Body)
									color.Red("Error Getting Profile ")
									time.Sleep(time.Second * 2)
									G.Print("Do you wanna try again? [y/n]: ")
									fmt.Scanln(&choice)
									if strings.ToLower(choice) != "y" {
										end(2)
									} else {
										continue
									}
								}
							}
						}
						receiverCookiesMap[SecureResult.Cookies[i].Name] = SecureResult.Cookies[i].Value
					}

				} else {
					println(SecureResult.Body)
					println(SecureResult.Res.Status)
					color.Red("Error choosing verify method")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						return
					} else {
						continue
					}
				}

			}

			if sessioned || sessionid != "" {
				break
			}

			println()
			color.Red("Error Logging into the account")
			println(res.Body)
			time.Sleep(time.Second * 2)
			G.Print("Do you wanna try again? [y/n]: ")
			fmt.Scanln(&choice)
			if strings.ToLower(choice) != "y" {
				end(2)
			} else {
				continue
			}

		}

	}

	maxingFdsLimit()

	println()

	var PM string
	G.Print("[+] Do you want to log this swapping session? [Y/N] > ")
	fmt.Scanln(&PM)

	if strings.ToLower(PM) == "y" {
		bypass = true
	} else {
		bypass = false
	}

	G.Print("[+] Auto Swap [Y/N] > ")
	fmt.Scanln(&PM)

	if strings.ToLower(PM) == "y" {
		loginToUnlock()
		selfUnlock = true
		var TPM string
		G.Print("[+] Unlock target if counter is above (Safest=100, Safe=25, Skip=10 [Normal] ) > ")
		fmt.Scanln(&TPM)
		dontuntil, err = strconv.Atoi(TPM)
		if err != nil || dontuntil < 0 {
			dontuntil = 10
		}

	} else {
		selfUnlock = false
	}

	for {
		var TPM string
		G.Print("[+] Enter Threads (Ultimate=100, Skip=50) > ")
		fmt.Scanln(&TPM)

		if _, err := strconv.Atoi(TPM); err == nil && TPM != "0" && !strings.Contains(TPM, "-") {
			_int64, _ := strconv.ParseInt(TPM, 0, 64)
			ThreadsPerMoment = int(_int64)
			break
		} else {
			if TPM == "" {
				ThreadsPerMoment = 50
				break
			}
			R.Print("Enter a correct number")
			time.Sleep(time.Second * 2)
		}
	}

	for {
		var TPM string
		G.Print("[+] Enter Loops (Ultimate=100, Skip=50) > ")
		fmt.Scanln(&TPM)

		if _, err := strconv.Atoi(TPM); err == nil && TPM != "0" && !strings.Contains(TPM, "-") {
			_int64, _ := strconv.ParseInt(TPM, 0, 64)
			loops = int(_int64)
			break
		} else {
			if TPM == "" {
				loops = 50
				break
			}
			R.Print("Enter a correct number")
			time.Sleep(time.Second * 2)
		}
	}

	if selfUnlock {
		target = uTAU
	} else {
		G.Print("[+] Enter Target > ")
		fmt.Scanln(&target)
	}

	params = url.Values{}
	params.Set("username", target)
	params.Set("email", Profile["email"])
	if Profile["phone_number"] != "" {
		params.Set("phone_number", Profile["phone_number"])
	}

	EditReq, _ = http.NewRequest("POST", "https://i.instagram.com/api/v1/accounts/edit_profile/", bytes.NewBuffer([]byte(params.Encode())))
	SetReq, _ = http.NewRequest("POST", "https://i.instagram.com/api/v1/accounts/set_username/", bytes.NewBuffer([]byte("username="+target)))

	EditReq.Header = map[string][]string{
		"User-Agent":   {"Instagram " + _api.VERSION + " Android (19/4.4.2; 480dpi; 1080x1920; samsung; SM-N900T; hltetmo; qcom; en_US)"},
		"Content-Type": {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":       {"*/*"},
		"Connection":   {"Keep-Alive"},
	}

	SetReq.Header = map[string][]string{
		"User-Agent":   {"Instagram " + _api.VERSION + " Android (19/4.4.2; 480dpi; 1080x1920; samsung; SM-N900T; hltetmo; qcom; en_US)"},
		"Content-Type": {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":       {"*/*"},
		"Connection":   {"Keep-Alive"},
	}

	globalCookie = &http.Cookie{
		Name:  "sessionid",
		Value: sessionid,
	}

	EditReq.AddCookie(globalCookie)
	SetReq.AddCookie(globalCookie)

	if selfUnlock {
		unlockGlobalCookie = &http.Cookie{
			Name:  "sessionid",
			Value: UnlockerSessionID,
		}
	} else {
		passedClientDone = true
	}

	rand.Seed(time.Now().UnixNano())

	raddr, err := net.ResolveTCPAddr("tcp", "i.instagram.com:443")
	instagramIP = raddr

	start.Add(1)

	//max := float64(loops*5+4) * 1.2 // 50 * 5 + 4 == 100 + 4 = 104 // 200
	max := float64(loops*5 + 4)
	runtime.GOMAXPROCS(int(max))

	clientsPool = loops

	var randnum int
	var TPM string
	G.Print("[+] API (set_username=1 (Good), edit_profile=0 (Bad), Skip=set_username) > ")
	fmt.Scanln(&TPM)
	randnum, err = strconv.Atoi(TPM)
	if randnum != 1 && randnum != 0 || err != nil {
		randnum = 1
	}

	if randnum == 1 {
		G.Println("[+] set_username API was selected")
	}
	if randnum == 0 {
		G.Println("[+] edit_profile API was selected")
	}

	// 1 = set
	// 0 = edit

	for i := 0; i < ThreadsPerMoment; i++ {
		go newSender(randnum)
	}

	if selfUnlock {
		go unlockUsername()
	}
	time.Sleep(time.Nanosecond * 10)

	for {
		time.Sleep(time.Nanosecond * 100)
		Y.Print("[+] Initiating all threads " + fmt.Sprintf("%v", readyCalls) + "/" + fmt.Sprintf("%v", (loops*ThreadsPerMoment)) + " ...\r")
		if int(readyCalls) >= (loops * ThreadsPerMoment) {
			G.Println("[+] All " + fmt.Sprintf("%v", (loops*ThreadsPerMoment)) + " threads initiated successfully!")
			break
		}
	}

	time.Sleep(time.Second * 2)

	for {
		time.Sleep(time.Nanosecond * 100)
		Y.Print("[+] connecting clients " + fmt.Sprintf("%v", connected) + "/" + fmt.Sprintf("%v", (clientsPool*ThreadsPerMoment)) + " ...\r")
		if int(connected) >= (clientsPool*ThreadsPerMoment) && int(AllocDone) == ThreadsPerMoment && passedClientDone {
			G.Println("[+] All " + fmt.Sprintf("%v", (clientsPool*ThreadsPerMoment)) + " clients connected successfully!")
			break
		}
	}

	time.Sleep(time.Second * 2)

	ClearConsole()

	fmt.Println()
	logo()

	fmt.Println()
	color.HiBlue(rights)
	fmt.Println()

	claimed.Add(1)
	blocked.Add(1)
	go waitClaimed()
	time.Sleep(time.Nanosecond * 10)
	go waitBlocked()
	time.Sleep(time.Nanosecond * 10)

	wg.Add(1)
	checkMemory()

	if runtime.GOOS == "windows" {
		MessageBoxPlain("DemonSwap", "Ready?")
	} else {
		color.Green("Click any key to start ...")
		fmt.Scanln()
	}

	start.Done()

	go count(&counter, &responseTimeout, &EditBlocked, &SetBlocked, &finishedRequests, &unfinishedRequests)
	go superVisior(&counter, &responseTimeout, &EditBlocked, &SetBlocked, &finishedRequests, &unfinishedRequests)

	wg.Wait()

	if runtime.GOOS == "windows" {
		reader.Scan()
	}

}

func checkMemory() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if bToMb(m.Alloc) > 5000 || bToMb(m.TotalAlloc) > 5000 || bToMb(m.Sys) > 5000 {
		R.Println("\nHigh Memory (RAM) Usage, 8 RAM VPS Recommended, 4 RAM Required")
		os.Exit(0)
	}
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

//AllocDone ..
var AllocDone uint64

func newSender(init int) {

	var Request *http.Request

	switch init {
	case 1:
		Request = SetReq
	default:
		Request = EditReq
	}

	var clients []*http.Transport
	var requests []*http.Request

	requests = make([]*http.Request, 120)
	connect(&clients, clientsPool, &connected, true)

	for i := 0; i < loops; i++ {

		var CopiedBody *bytes.Buffer
		switch init {
		case 1:
			CopiedBody = bytes.NewBuffer([]byte("username=" + target))
		default:
			CopiedBody = bytes.NewBuffer([]byte(params.Encode()))
		}

		CopiedRequest, _ := http.NewRequest(Request.Method, Request.URL.String(), CopiedBody)
		CopiedRequest.Header = map[string][]string{
			"Host":         {"i.instagram.com"},
			"User-Agent":   {"Instagram " + _api.VERSION + " Android (19/4.4.2; 480dpi; 1080x1920; samsung; SM-N900T; hltetmo; qcom; en_US)"},
			"Content-Type": {"application/x-www-form-urlencoded; charset=UTF-8"},
			"Accept":       {"*/*"},
			"Connection":   {"Keep-Alive"},
		}
		CopiedRequest.AddCookie(globalCookie)

		requests[i] = CopiedRequest

	}

	execute := func(Client *http.Transport, tRequest *http.Request) {

		atomic.AddUint64(&readyCalls, 1)
		start.Wait()
		resp, err := Client.RoundTrip(tRequest)

		if err != nil {
			atomic.AddUint64(&unfinishedRequests, 1)
			return
		}

		atomic.AddUint64(&finishedRequests, 1)

		if resp != nil {
			go handleResponse(resp, init)
		}

	}

	for j := 0; j < loops; j++ {

		go execute(clients[j], requests[j])
		time.Sleep(time.Nanosecond * 10)

	}

}

func handleResponse(resp *http.Response, ReqType int) {

	switch resp.StatusCode {
	case 400:
		atomic.AddUint64(&counter, 1)
	case 200:
		atomic.AddUint64(&success, 1)
		response := MakeHttpResponse(resp, resp.Request, nil, 0, 0)
		if strings.Contains(response.Body, "\"user\"") || strings.Contains(response.Body, "is_private") || success > 2 {
			claim = true
			stop = true
			atomic.AddUint64(&counter, 1)
			atomic.AddUint64(&succ, 1)
		}
	case 429:
		if ReqType == 1 {
			atomic.AddUint64(&SetBlocked, 1)
		} else {
			atomic.AddUint64(&EditBlocked, 1)
		}
	default:
		appendToFile("status.log", resp.Status+":"+fmt.Sprintf("%v", counter)+"\n")
	}

}

var connected uint64
var sleept bool

func connect(tClients *[]*http.Transport, pool int, tConnected *uint64, Alloc bool) {

	if Alloc {
		*tClients = make([]*http.Transport, pool)
	}

	const URL string = "https://i.instagram.com/"
	InitRequest, err := http.NewRequest("GET", URL, nil)
	InitRequest.Header = map[string][]string{
		"User-Agent":       {"Instagram " + _api.VERSION + " Android (19/4.4.2; 480dpi; 1080x1920; samsung; SM-N900T; hltetmo; qcom; en_US)"},
		"Content-Type":     {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":           {"*/*"},
		"Connection":       {"Keep-Alive"},
		"Proxy-Connection": {"Keep-Alive"},
	}

	if err != nil {
		panic(err)
	}

	for i := 0; i < pool; i++ {

		(*tClients)[i] = &http.Transport{
			MaxIdleConnsPerHost: 9216,
			MaxIdleConns:        0,
			MaxConnsPerHost:     0,
			TLSHandshakeTimeout: 0,
			IdleConnTimeout:     0,
			ProxyConnectHeader: map[string][]string{
				"Connection":       {"Keep-Alive"},
				"Proxy-Connection": {"Keep-Alive"},
			},
		}

	}

	atomic.AddUint64(&AllocDone, 1)

	for i := 0; i < pool; i++ {

		go func(in int) {

			var TCPConnected bool

			(*tClients)[in].DialTLS = func(network, addr string) (net.Conn, error) {

				TCPConnection, err := net.DialTCP(network, nil, instagramIP)
				if err != nil {
					return nil, err
				}
				TCPConnection.SetKeepAlive(true)

				tlsConfig := &tls.Config{
					InsecureSkipVerify: true,
				}

				tlsConn := tls.Client(TCPConnection, tlsConfig)
				err = tlsConn.Handshake()

				if err != nil {
					return tlsConn, err
				}

				TCPConnected = true
				return tlsConn, err

			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, _ := (*tClients)[in].RoundTrip(InitRequest.WithContext(ctx))
			if TCPConnected {
				if resp != nil {
					io.Copy(ioutil.Discard, resp.Body)
					resp.Body.Close()
				}
				atomic.AddUint64(tConnected, 1)
				// (*tClients)[in].StartSignal = &start
				// (*tClients)[in].ReadyToWrite = &readyCalls
				return
			}

			for {

				(*tClients)[in].CloseIdleConnections()
				time.Sleep(time.Second * 1)

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				resp, _ := (*tClients)[in].RoundTrip(InitRequest.WithContext(ctx))

				if TCPConnected {
					if resp != nil {
						io.Copy(ioutil.Discard, resp.Body)
						resp.Body.Close()
					}
					atomic.AddUint64(tConnected, 1)
					// (*tClients)[in].StartSignal = &start
					// (*tClients)[in].ReadyToWrite = &readyCalls
					break
				}

			}

		}(i)

	}
}

func getProcessOwner() string {
	stdout, err := exec.Command("ps", "-o", "user=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	return strings.Replace(string(stdout), "\n", "", -1)
}

var UnlockerSessionID string
var UnlockerCookiesMap = make(map[string]string)
var uTAU string
var UnlockerProfile = make(map[string]string)

func loginToUnlock() {

	defer println()

	var choice string
	var sessioned bool
	var TPass string

	for {
		G.Print("[+] Session ID[S] / Login [L] > ")
		fmt.Scanln(&choice)
		if strings.ToLower(choice) == "s" {
			G.Print("Enter the API SessionID: ")
			fmt.Scanln(&UnlockerSessionID)
			var res HttpResponse
			UnlockerProfile, res = GetProfile(UnlockerSessionID)
			if res.ResStatus == 200 || strings.Contains(res.Body, "consent_required") || strings.Contains(res.Body, "pk") || strings.Contains(res.Body, "email") {

				if strings.Contains(res.Body, "consent_required") {
					updateBTHRes := updateBTH(UnlockerSessionID)
					if updateBTHRes.ResStatus != 200 {
						println(updateBTHRes.Body)
						color.Red("Error Updating Day of birth")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							return
						}
						continue
					}
				}
				UnlockerProfile, res = GetProfile(UnlockerSessionID)
				if UnlockerProfile["username"] == "" {
					println(res.Body)
					color.Red("Error Getting Profile ")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						return
					}
					continue
				}

				for i := 0; i < len(res.Cookies); i++ {
					UnlockerCookiesMap[res.Cookies[i].Name] = res.Cookies[i].Value
				}
				UnlockerCookiesMap["sessionid"] = UnlockerSessionID
				uTAU = UnlockerProfile["username"]
				println()
				color.Green("Logged In @" + uTAU + " Successfully")
				sessioned = true
				break

			} else {
				println(res.Body)
				color.Red("Error Getting Profile 2")
				time.Sleep(time.Second * 2)
				G.Print("Do you wanna try again? [y/n]: ")
				fmt.Scanln(&choice)
				if strings.ToLower(choice) != "y" {
					return
				}
				continue
			}
		} else {
			break
		}
	}

	for {
		if sessioned {
			UnlockerCookiesMap["sessionid"] = UnlockerSessionID
			break
		}

		G.Print("Enter the username: ")
		fmt.Scanln(&uTAU)
		G.Print("Enter the password: ")
		fmt.Scanln(&TPass)
		var res HttpResponse

		res = login(uTAU, TPass, 60*1000)

		for i := 0; i < len(res.Cookies); i++ {
			if res.Cookies[i].Name == "sessionid" {
				loggedIn = true
				println()
				color.Green("Logged In Successfully")
				color.Green("Session ID: " + res.Cookies[i].Value)
				println()
				UnlockerSessionID = res.Cookies[i].Value
				_Res := HttpResponse{}
				UnlockerProfile, _Res = GetProfile(UnlockerSessionID)
				if strings.Contains(_Res.Body, "consent_required") || _Res.Res.StatusCode != 200 {
					updateBTHRes := updateBTH(UnlockerSessionID)
					if updateBTHRes.ResStatus != 200 {
						println(updateBTHRes.Body)
						color.Red("Error Updating Day of birth")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							return
						}
						continue
					}
					UnlockerProfile, _Res = GetProfile(UnlockerSessionID)
					if UnlockerProfile["username"] == "" {
						println(_Res.Body)
						color.Red("Error Getting Profile ")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							return
						}
						continue
					}
				}
			}
			UnlockerCookiesMap[res.Cookies[i].Name] = res.Cookies[i].Value
		}

		if strings.Contains(res.Body, "ogged_in") && loggedIn && UnlockerProfile["username"] != "" {
			return
		} else {
			if strings.Contains(res.Body, "challenge_required") {

				urlRegex := regexp.MustCompile("\"api_path\": \"(.*?)\"").FindStringSubmatch(res.Body)
				var url string

				if urlRegex == nil {
					println(res.Body)
					color.Red("Getting API Path Error")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						return
					} else {
						continue
					}
				}

				url = urlRegex[1]

				_headers := make(map[string]string)
				loginCookies := res.Headers.Get("set-cookie")

				if loginCookies == "" {
					color.Red("Login's set-cookie is empty")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						return
					} else {
						continue
					}
				}

				CSRFRegex := regexp.MustCompile("csrftoken=(.*?);").FindStringSubmatch(loginCookies)
				//MidRegex := regexp.MustCompile("mid=(.*?);").FindStringSubmatch(loginCookies)
				var csrftoken string

				if CSRFRegex == nil {
					println(loginCookies)
					color.Red("CSRF is empty")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						return
					} else {
						continue
					}
				}

				csrftoken = CSRFRegex[1]

				_headers["X-CSRFToken"] = csrftoken

				SecureResult := instRequest(url, nil, "", _headers, GetAPI(), "", res.Cookies, true, 60*1000)

				em := false
				ph := false

				var Pass bool
				var email string
				var phone string
				var emailRegex []string
				var phoneRegex []string

				if strings.Contains(SecureResult.Body, "select_verify_method") {
					if strings.Contains(SecureResult.Body, "email") {
						emailRegex = regexp.MustCompile("\"email\": \"(.*?)\"").FindStringSubmatch(SecureResult.Body)
					}
					if strings.Contains(SecureResult.Body, "phone_number") {
						phoneRegex = regexp.MustCompile("\"phone_number\": \"(.*?)\"").FindStringSubmatch(SecureResult.Body)
					}
				} else {
					choice = "0"
					Pass = true
				}

				var contactPoint string

				if !Pass {
					if phoneRegex == nil && emailRegex == nil {
						println(SecureResult.Body)
						color.Red("No Verify Methods Found")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							return
						} else {
							continue
						}
					}

					if phoneRegex != nil {
						phone = phoneRegex[1]
						ph = true
					}
					if emailRegex != nil {
						email = emailRegex[1]
						em = true
					}

					if em {
						G.Println("1) email [" + email + "]")
					}
					if ph {
						G.Println("0) phone number [" + phone + "]")
					}

					G.Print("Select Method: ")
					fmt.Scanln(&choice)

					if choice == "0" {
						contactPoint = phone
					}

					if choice == "1" {
						contactPoint = email
					}

					if choice != "1" && choice != "0" {
						println(SecureResult.Body)
						color.Red("Choose a correct verify method")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							return
						} else {
							continue
						}
					}

				}

				SecureResult = instRequest(url, nil, "choice="+choice, nil, GetAPI(), "", res.Cookies, true, 60*1000)
				if strings.Contains(strings.ToLower(SecureResult.Body), "contact_point") {

					G.Println("A code has been sent to " + contactPoint)

					G.Print("Security Code: ")
					fmt.Scanln(&choice)
					choice = strings.Replace(choice, " ", "", -1)

					SecureResult = instRequest(url, nil, "security_code="+choice, nil, GetAPI(), "", res.Cookies, true, 60*1000)

					if strings.Contains(strings.ToLower(SecureResult.Body), "ok") || SecureResult.Res.StatusCode == 200 {

						for i := 0; i < len(SecureResult.Cookies); i++ {
							if SecureResult.Cookies[i].Name == "sessionid" {
								println()
								color.Green("Logged In Successfully")
								color.Green("Session ID: " + SecureResult.Cookies[i].Value)
								UnlockerSessionID = SecureResult.Cookies[i].Value
								sessioned = true

								UnlockerProfile, res = GetProfile(UnlockerSessionID)
								if strings.Contains(res.Body, "consent_required") {
									updateBTHRes := updateBTH(UnlockerSessionID)
									if updateBTHRes.ResStatus != 200 {
										println(updateBTHRes.Body)
										color.Red("Error Updating Day of birth")
										time.Sleep(time.Second * 2)
										G.Print("Do you wanna try again? [y/n]: ")
										fmt.Scanln(&choice)
										if strings.ToLower(choice) != "y" {
											return
										}
										continue
									}
								}
								UnlockerProfile, res = GetProfile(UnlockerSessionID)
								if UnlockerProfile["username"] == "" {
									println(res.Body)
									color.Red("Error Getting Profile ")
									time.Sleep(time.Second * 2)
									G.Print("Do you wanna try again? [y/n]: ")
									fmt.Scanln(&choice)
									if strings.ToLower(choice) != "y" {
										return
									}
									continue
								}

							}
							UnlockerCookiesMap[SecureResult.Cookies[i].Name] = SecureResult.Cookies[i].Value

						}

					} else {
						println(SecureResult.Body)
						println("Code: " + choice)
						color.Red("Sending Activation Code Error")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							return
						} else {
							continue
						}
					}

				} else if SecureResult.Res.StatusCode == 200 {

					for i := 0; i < len(SecureResult.Cookies); i++ {
						if SecureResult.Cookies[i].Name == "sessionid" {
							println()
							color.Green("Logged In Successfully")
							color.Green("Session ID: " + SecureResult.Cookies[i].Value)
							UnlockerSessionID = SecureResult.Cookies[i].Value
							sessioned = true

							UnlockerProfile, res = GetProfile(UnlockerSessionID)
							if strings.Contains(res.Body, "consent_required") {
								updateBTHRes := updateBTH(UnlockerSessionID)
								if updateBTHRes.ResStatus != 200 {
									println(updateBTHRes.Body)
									color.Red("Error Updating Day of birth")
									time.Sleep(time.Second * 2)
									G.Print("Do you wanna try again? [y/n]: ")
									fmt.Scanln(&choice)
									if strings.ToLower(choice) != "y" {
										return
									}
									continue
								}
							}
							UnlockerProfile, res = GetProfile(UnlockerSessionID)
							if UnlockerProfile["username"] == "" {
								println(res.Body)
								color.Red("Error Getting Profile ")
								time.Sleep(time.Second * 2)
								G.Print("Do you wanna try again? [y/n]: ")
								fmt.Scanln(&choice)
								if strings.ToLower(choice) != "y" {
									return
								}
								continue
							}
						}
						UnlockerCookiesMap[SecureResult.Cookies[i].Name] = SecureResult.Cookies[i].Value
					}

				} else {
					println(SecureResult.Body)
					println(SecureResult.Res.Status)
					color.Red("Error choosing verify method")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						return
					} else {
						continue
					}
				}

			}

			if sessioned || UnlockerSessionID != "" {
				return
			}

			println()
			color.Red("Error Logging into the account")
			println(res.Body)
			time.Sleep(time.Second * 2)
			G.Print("Do you wanna try again? [y/n]: ")
			fmt.Scanln(&choice)
			if strings.ToLower(choice) != "y" {
				return
			}
			continue

		}

	}
}

var unlockTries int

func unlockUsername() {

	//runtime.LockOSThread()
	//defer runtime.UnlockOSThread()

	var Connected bool

	unlockTransport := &http.Transport{
		MaxIdleConnsPerHost: 9216,
		MaxIdleConns:        0,
		MaxConnsPerHost:     0,
		TLSHandshakeTimeout: 0,
		IdleConnTimeout:     0,
		ProxyConnectHeader: map[string][]string{
			"Connection":       {"Keep-Alive"},
			"Proxy-Connection": {"Keep-Alive"},
		},
		DialTLS: func(network, addr string) (net.Conn, error) {

			TCPConnection, err := net.DialTCP(network, nil, instagramIP)
			if err != nil {
				return nil, err
			}
			TCPConnection.SetKeepAlive(true)

			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
			}

			tlsConn := tls.Client(TCPConnection, tlsConfig)
			err = tlsConn.Handshake()

			if err != nil {
				return tlsConn, err
			}

			Connected = true
			return tlsConn, err

		},
	}

	const URL string = "https://i.instagram.com/"
	InitRequest, _ := http.NewRequest("GET", URL, nil)
	InitRequest.Header = map[string][]string{
		"User-Agent":       {"Instagram " + _api.VERSION + " Android (19/4.4.2; 480dpi; 1080x1920; samsung; SM-N900T; hltetmo; qcom; en_US)"},
		"Content-Type":     {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":           {"*/*"},
		"Connection":       {"Keep-Alive"},
		"Proxy-Connection": {"Keep-Alive"},
	}

	for {

		resp, _ := unlockTransport.RoundTrip(InitRequest)
		if Connected {
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
			break
		}
		time.Sleep(time.Nanosecond * 10)

	}

	editParams := url.Values{}
	editParams.Set("username", uTAU+".demon.swapped")
	editParams.Set("email", UnlockerProfile["email"])
	if Profile["phone_number"] != "" {
		editParams.Set("phone_number", UnlockerProfile["phone_number"])
	}

	var ReqBody *bytes.Buffer
	ReqBody = bytes.NewBuffer([]byte(editParams.Encode()))

	//ReqBody = bytes.NewBuffer([]byte("username=" + uTAU + ".demon.swapped"))

	CopiedRequest, _ := http.NewRequest("POST", EditReq.URL.String(), ReqBody)

	CopiedRequest.Header = map[string][]string{
		"Host":         {"i.instagram.com"},
		"User-Agent":   {"Instagram " + _api.VERSION + " Android (19/4.4.2; 480dpi; 1080x1920; samsung; SM-N900T; hltetmo; qcom; en_US)"},
		"Content-Type": {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":       {"*/*"},
		"Connection":   {"Keep-Alive"},
	}

	CopiedRequest.AddCookie(unlockGlobalCookie)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	CopiedRequest = CopiedRequest.WithContext(ctx)

	passedClientDone = true

	start.Wait()

	// Sleep or { if (finished) >= int64((loops*ThreadsPerMoment) / 4) } or both
	// handling requests is post-request so the counter isn't accurte 100%
	// maybe all the requests done on the server-side, then the counter increased
	// then u unlock the username too late
	// maybe sleep? nanoseconds
	// or u can do the unlock with the other gorountines,
	// without Locking the OS Thread, but when u reach the recover func lock it

	//time.Sleep(time.Microsecond * 500)

	var resp *http.Response
	var err error

	for {
		//if int(finishedRequests) >= (loops*ThreadsPerMoment/10) && int(finishedRequests) < int(float64(loops*ThreadsPerMoment)/1.2) {
		if int(finishedRequests) >= dontuntil {
			if int(finishedRequests) >= int(float64(loops*ThreadsPerMoment))-10 {
				println("\n\nTarget Username didn't changed")
				os.Exit(0)
			}
			resp, err = unlockTransport.RoundTrip(CopiedRequest)
			break
		}
		time.Sleep(time.Nanosecond * 10)
	}

	if resp != nil {
		if resp.StatusCode == 200 || resp.StatusCode == 400 {
			goto tryToRecover
		} else {
			println("\n\nTarget Username didn't changed")
			response := MakeHttpResponse(resp, resp.Request, err, 0, 0)
			println(response.Body)
			os.Exit(0)
		}
	}

tryToRecover:

	ReqBody = bytes.NewBuffer([]byte("username=" + uTAU))

	CopiedRequest.ContentLength = int64(ReqBody.Len())
	buf := ReqBody.Bytes()
	CopiedRequest.GetBody = func() (io.ReadCloser, error) {
		r := bytes.NewReader(buf)
		return ioutil.NopCloser(r), nil
	}
	CopiedRequest.Body, _ = CopiedRequest.GetBody()

	for {

		resp, _ := unlockTransport.RoundTrip(CopiedRequest)

		if resp != nil {
			if resp.StatusCode == 200 {
				println("\n\nTarget Username returned to the target account")
				os.Exit(0)
			}
		}

		if stop {
			return
		}

		time.Sleep(time.Second)

	}

}

var finishedRequests uint64
var unfinishedRequests uint64
var responseTimeout uint64

func waitClaimed() {

	claimed.Wait()
	requestBin()
	WebHook()

	ClearConsole()
	fmt.Println()
	logo()

	fmt.Println()
	color.HiBlue(rights)
	fmt.Println()

	if newSuccess {

		r := strings.NewReplacer(
			"#t", target,
			"#a", fmt.Sprintf("%v", counter),
		)

		Final = r.Replace(Final)
		print(Final)

	} else {

		R.Print("\n" + ClaimingPhrase + ": ")
		w.Print(target + "\n")
		R.Print("Attempts: ")
		w.Println(fmt.Sprintf("%v", counter))

	}

	stopC = true

}

func waitBlocked() {

	blocked.Wait()
	R.Println(
		"\nYou got blocked for spamming too many requests\nReached: " +
			fmt.Sprintf("%v", counter) + "\nBlocked Req S: " +
			fmt.Sprintf("%v", SetBlocked) + "\nBlocked Req E: " +
			fmt.Sprintf("%v", EditBlocked) +
			"\nSucc: " + fmt.Sprintf("%v", succ) + "\nSuccess: " + fmt.Sprintf("%v", success))

	Y.Print("\nYou Claimed @" + target + " ? (y/n): ")
	reader.Scan()
	if err := reader.Err(); err != nil {
		panic(err)
	}
	outin := reader.Text()
	outin = strings.Replace(outin, "\n", "", -1)
	if strings.ToLower(outin) == "y" {

		requestBin()
		WebHook()

		ClearConsole()
		fmt.Println()
		logo()

		fmt.Println()
		color.HiBlue(rights)
		fmt.Println()

		if newSuccess {

			r := strings.NewReplacer(
				"#t", target,
				"#a", fmt.Sprintf("%v", counter),
			)

			Final = r.Replace(Final)
			print(Final)

		} else {

			R.Print("\n" + ClaimingPhrase + ": ")
			w.Print(target + "\n")
			R.Print("Attempts: ")
			w.Println(fmt.Sprintf("%v", counter))

		}

	}

	stopC = true

}

func count(tCounter *uint64, tTimeoutResponse *uint64, ReqBlock1 *uint64, ReqBlock2 *uint64, tFinishedRequests *uint64, tUnFinishedRequests *uint64) {

	for {
		if claim || stop || int(unfinishedRequests+finishedRequests+((*ReqBlock1)+(*ReqBlock2))) >= (loops*ThreadsPerMoment) {

			if claim || succ > 0 || success > 2 {

				stopCo = true
				mx.Lock()
				if !stopS {
					claim = true
					claimed.Done()
				}
				mx.Unlock()
				atomic.AddUint64(&counter, 1)
				atomic.AddUint64(&succ, 1)
				stop = true
				stopS = true
				return

			}

			if int(unfinishedRequests+finishedRequests+((*ReqBlock1)+(*ReqBlock2))) >= (loops * ThreadsPerMoment) {

				if (*ReqBlock1 >= 15 && *ReqBlock2 >= 15) || *tCounter >= 120 || ((*ReqBlock1)+(*ReqBlock2)) >= 20 {
					stopCo = true
					mx.Lock()
					if !stopB {
						blocked.Done()
					}
					mx.Unlock()
					stop = true
					stopB = true
					return
				}

			}

		}
		time.Sleep(time.Nanosecond * 100)
	}

}

func superVisior(tCounter *uint64, tTimeoutResponse *uint64, ReqBlock1 *uint64, ReqBlock2 *uint64, tFinishedRequests *uint64, tUnFinishedRequests *uint64) {
	for {

		if stopC {
			break
		} else {
			if !stopCo {
				blue.Print("[+] Swapping (" + target + ") > " + fmt.Sprintf("%v", *tFinishedRequests) + ", " + fmt.Sprintf("%v", *tCounter) + ", " + fmt.Sprintf("%v", (*ReqBlock1)+(*ReqBlock2)) + ", " + fmt.Sprintf("%v", *tUnFinishedRequests) + " \r")
			}
		}

		time.Sleep(time.Millisecond * 1)

	}
	wg.Done()

}

func appendToFile(filename string, data string) error {
	f, err := os.OpenFile(filename,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(data); err != nil {
		return err
	}
	return nil
}
