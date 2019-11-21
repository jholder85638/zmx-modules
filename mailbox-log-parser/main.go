//Copyright (C) 2019  John Holder (jholder@zimbra.com)
//
//This program is free software: you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program.  If not, see <http://www.gnu.org/licenses/>.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"github.com/OneOfOne/cmap"
	"github.com/cheggaaa/pb/v3"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"regexp"
	"time"
	_ "time"

	"gopkg.in/ini.v1"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

type ScanByteCounter struct {
	BytesRead int
}

func (s *ScanByteCounter) Wrap(split bufio.SplitFunc) bufio.SplitFunc {
	return func(data []byte, atEOF bool) (int, []byte, error) {
		adv, tok, err := split(data, atEOF)
		s.BytesRead += adv
		return adv, tok, err
	}
}

type count32 int32

func (c *count32) increment() int32 {
	return atomic.AddInt32((*int32)(c), 1)
}
func (c *count32) get() int32 {
	return atomic.LoadInt32((*int32)(c))
}

var SeverityCounts *cmap.CMap
var AllDetailMapper *cmap.CMap
var SanitizeIgnoreMissing bool
var SanitizeKeepOriginalValuesForKeys []string
var SanitizeOverrideFuncKeys []string
var SanitizeMapper map[string]string
var prevString string
func GetFileContentType(out *os.File) (string, error) {

	// Only the first 512 bytes are used to sniff the content type.
	buffer := make([]byte, 512)

	_, err := out.Read(buffer)
	if err != nil {
		return "", err
	}

	// Use the net/http package's handy DectectContentType function. Always returns a valid
	// content-type by returning "application/octet-stream" if no others seemed to match.
	contentType := http.DetectContentType(buffer)

	return contentType, nil
}
func main() {
	var err error
	logFile := flag.String("log", "/opt/zimbra/log/mailbox.log", "a string")

	//maxTime := flag.String("max-time", "0", "-max-time=45")
	flag.Parse()
	cfg, err := ini.Load("sanitize_rules.ini")
	if err != nil {
		fmt.Printf("Fail to read file: %v", err)
		os.Exit(1)
	}
	InitSanitizeRules(cfg)
	f, err := os.OpenFile(*logFile, os.O_RDONLY, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	contentType, err := GetFileContentType(f)
	if err != nil {
		log.Fatalf("open file error: %v", err)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		log.Fatal(err) // Could not obtain stat, handle error
	}
	fileSize := fi.Size()
	SeverityCounts = cmap.New() // or cmap.NewString()
	AllDetailMapper = cmap.New() // or cmap.NewString()
	var sc *bufio.Scanner
	buf := make([]byte, 0, 64*4096)

	if contentType=="application/x-gzip"{
		log.Println("File type is Gzip.")
		log.Println("Note: If the uncompressed file is over 4GB, the progressbar can be wrong.")
		log.Println("This is an issue with the gzip format and not this program.")
		f.Seek(0, os.SEEK_SET)
		gz, err := gzip.NewReader(f)
		if err !=nil{
			log.Fatal(err)
		}
		fileSize = GetUncompressedFileSize(*logFile)
		sc = bufio.NewScanner(gz)
		sc.Buffer(buf, bufio.MaxScanTokenSize)

	}else{
		sc = bufio.NewScanner(f)
		sc.Buffer(buf, bufio.MaxScanTokenSize)

	}
	//sc := bufio.NewScanner(f)
	//buf := make([]byte, 24)
	//scanner.Buffer(buf, 1024*1024)
	counter := ScanByteCounter{}
	splitFunc := counter.Wrap(bufio.ScanLines)
	sc.Split(splitFunc)
	ProgressBarTemplate := `{{` + "test" + ` . "prefix"}} {{counters . }} {{bar . }} {{percent . }} {{speed . }} {{rtime . "ETA %s"}}{{string . "suffix"}}`
	bar := pb.New(int(fileSize))
	tmpl := bar.SetTemplateString(ProgressBarTemplate)
	bar.Set(pb.Bytes, true)
	bar.Start()
	ThrottleUpdateCounter := count32(0)
	useThrottleUpdate := true
	ThrottleUpdate := 15000
	Timeout := time.Second*5
	start := time.Now()
	useTimer := false
	LineScanned := count32(0)

	for sc.Scan() {

		bar.SetCurrent(int64(counter.BytesRead))

		if bytes.HasPrefix([]byte(" "), sc.Bytes()) {
			continue
		}
		//else if strings.Contains(sc.Text(), " INFO "){
		//	continue
		//}else if strings.Contains(sc.Text(), "index - Unable to index: "){
		//	continue
		//}

		shouldContinue := CheckLineValidity(sc.Bytes())

		if !shouldContinue {
			continue
		}
		thisLine := LineScanned.get()
		if useThrottleUpdate {
			if ThrottleUpdate == int(ThrottleUpdateCounter) {
				UpdateProgressbarCounters(SeverityCounts, thisLine, tmpl, counter)
				LineScanned += ThrottleUpdateCounter
				ThrottleUpdateCounter = count32(0)
				if useTimer{
					if time.Since(start) > Timeout {
						break
					}
				}

			} else {
				ThrottleUpdateCounter.increment()
			}
		}
		thisText := sc.Text()
		thisText = strings.Replace(thisText, "  ", " ", -1)
		UpdateSeverityCounters(sc.Bytes())
	}
	if err := sc.Err(); err != nil {
		log.Printf("Error reading line: %v", err)
	}
	tmpl.Finish()

	AllDetailKeys := AllDetailMapper.Keys()
	fmt.Println("Severity\tComponent\tMessage\tCount")
	for _, v := range AllDetailKeys {
		//thisLine := strings.Replace(v.(string), ",","_",-1)
		thisLine := strings.Replace(v.(string), "|ZMD|","\t",-1)
		if !strings.Contains(thisLine, "\t\t"){
			fmt.Println(thisLine+"\t"+strconv.Itoa(AllDetailMapper.Get(v.(string)).(int)))

		}
	}
}

func GetUncompressedFileSize(s string) int64 {
		var fileSize int64
		fileSize = 0
		out, err := exec.Command("gunzip","-l", s).Output()
		if err != nil {
			log.Fatal(err)
		}
		output := strings.Split(string(out), "\n")
		space := regexp.MustCompile(`\s+`)
		s = strings.Split(space.ReplaceAllString(output[1], " "), " ")[2]
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			fileSize = n
		}
		if err != nil {
			log.Print(err)
		}
		return fileSize
}
func InitSanitizeRules(file *ini.File) {
	SanitizeIgnoreMissing = file.Section("DEFAULT").Key("IgnoreMissing").MustBool(true)
	SanitizeMapper = make(map[string]string)
	for _, v := range file.Section("REPLACEMENTS").KeyStrings() {
		value, err := file.Section("REPLACEMENTS").GetKey(v)
		if err != nil {

		} else {
			SanitizeMapper[v] = value.String()
		}
	}

	for _, v := range file.Section("OVERRIDE").KeyStrings() {
		SanitizeOverrideFuncKeys = append(SanitizeOverrideFuncKeys, v)
	}

	for _, v := range file.Section("ORIGINAL").KeyStrings() {
		SanitizeKeepOriginalValuesForKeys = append(SanitizeKeepOriginalValuesForKeys, v)
	}
}

func CheckLineValidity(i []byte) bool {
	shouldContinue := false
	if bytes.HasPrefix(i, []byte("2019")) {
		shouldContinue = true
	}

	if bytes.HasPrefix(i, []byte("ExceptionId")) {
		shouldContinue = false
	}
	if bytes.HasPrefix(i, []byte("Caused")) {
		shouldContinue = false
	}
	return shouldContinue
}

func UpdateProgressbarCounters(SeverityCounts *cmap.CMap, ls int32, bar *pb.ProgressBar, counter ScanByteCounter) {
	StatusString := CalculatePercentages(SeverityCounts)
	bar.Set("prefix", "Lines: "+strconv.Itoa(int(ls))+" "+StatusString)
}

func repNums(s string, bts []byte) string {

	//TODO: 50% performance hit
	//original := s
	//if strings.Contains(s, "@") {
	//	re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	//	s = re.ReplaceAllString(s, "{email}")
	//}
	if bytes.HasPrefix([]byte(s), []byte("Delivering message: ")) {
		s = "Delivering message: size={size}} bytes, nrcpts={recipients}, sender{sender}, msgid={Message-Id}}"
	} else if bytes.HasPrefix([]byte(s), []byte("Adding Message: id=")) {
		s = "Adding Message: id={item id}, Message-ID={Message-Id}, parentId={parent item id}, folderId={folder id}, folderName={folder name}."
	}
	returnVal := s
	if strings.Contains(returnVal, "invalid metadata: ") {
		returnVal = "invalid metadata: {metadata}"
	}else

	if strings.Contains(returnVal, "Slow execution ") {
		returnVal = "Slow execution ({query time}ms): {query}"
	}else if strings.Contains(returnVal, "child[Message") {
		if strings.Contains(returnVal, "till associated with conv") {
			returnVal = "child[Message{item id}] type[5] subject[{subject}] in folder[{folder id}}] " +
				"still associated with conv [{conversation id}]"
		} else {
			returnVal = "child[Message{item id}] type[5] subject[{subject}] in folder[{folder id}}] " +
				"{unknown error, not logged}"

		}
		return returnVal
	}

	if strings.Contains(returnVal, "Upload: ") {
		returnVal = "Received/Save: Upload: { accountId={zimbraId}, time={time}, size={size}, uploadId={uid}, name={filename},path=/opt/zimbra/data/tmp/upload/{id}}"
		return returnVal
	}

	//TODO: 15% performance hit
	returnVal = ResolveNumIntegerUsingContext(returnVal)
	returnVal = ResolveNumberUsingKVP(returnVal)

	if strings.Contains(string(bts), "Deleting items: ") {
		returnVal = "Deleting items: {item ids}."
	}
	if strings.Contains(returnVal, "@") {
		splitter := strings.Split(returnVal, " ")
		for _, v := range splitter {
			if strings.Contains(v, "@") {
				returnVal = strings.Replace(returnVal, v, "{email}", -1)
			}
		}

	}
	if strings.Contains(returnVal, "children"){
		if strings.Contains(returnVal, "["){
			original := strings.Split(returnVal, "[")
			returnVal = original[0]+"[{item id}] still has {count} children."
		}
	}

	if strings.Contains(returnVal, "FAILED") {
		original := strings.Split(returnVal, " ")
		for _,v := range original{
			if strings.Contains(v, "["){
				returnVal = strings.Replace(returnVal, v, "[{item id}]", -1)
			}
		}
	}
	if strings.Contains(returnVal, "failure item id[") {
		original := strings.Split(returnVal, "] ")
		targetReplacement := ""
		replacement := ""
		for _,v := range original{
			org2 := strings.Split(v, "[")
			targetReplacement += ""+v+"] "
			replacement +=	org2[0]+"[{value}] "
		}
		returnVal = replacement
	}
	if strings.Contains(returnVal, "All pending file IO completed") {
		original := strings.Split(returnVal, " (")
		returnVal = original[0]+" ({completed count} out of {total count})"
	}else
	if strings.Contains(returnVal, "mailop - Deleting Message (id="){
		returnVal = "mailop - Deleting Message (id={item id})"
	}

		return returnVal
}

func ResolveNumberUsingKVP(returnVal string) string {

	for _, v := range strings.Split(returnVal, " ") {
		if strings.Contains(v, "zimbraId") {
			continue
		}
		prevString = strings.Replace(v, ":", "", -1)
		if strings.Contains(v, "=") {
			if strings.Contains(v, "<") {
				tester := strings.Split(v, "<")
				if strings.Contains(tester[1], "=") {
					continue
				}

			}
			if !strings.Contains(v, "{") {
				kvp := strings.Split(v, "=")
				doReplacement := true
				doFuncOverride := false
				for _, v := range SanitizeKeepOriginalValuesForKeys {
					if kvp[0] == v {
						doReplacement = false
					}
				}
				for _, v := range SanitizeOverrideFuncKeys {
					if kvp[0] == v {
						doFuncOverride = true
					}
				}
				if doFuncOverride == true {
					returnVal = HandleCustomOverride([]byte("boop"))
					return returnVal
				}
				if !doReplacement {
					continue
				} else {
					if val, ok := SanitizeMapper[kvp[0]]; ok {
						returnVal = strings.Replace(returnVal, kvp[1], val, -1)
					}
				}
			}
		}
	}
	return returnVal
}

func ResolveNumIntegerUsingContext(returnVal string) string {

	for _, v := range strings.Split(returnVal, " ") {
		if strings.Contains(v, "-") {
			UIDTest := strings.Split(v, "-")
			if len(UIDTest) == 5 {
				returnVal = strings.Replace(returnVal, v, "{zimbraId}", -1)
			}
		}
	}
	for _, v := range strings.Split(returnVal, " ") {
		if !strings.Contains(v, "=") {
			if strings.Contains(v, ",") {
				v = strings.Split(v, ",")[0]
				if _, err := strconv.Atoi(v); err == nil {
					if val, ok := SanitizeMapper[strings.Replace(prevString, ":","",-1)]; ok {
						returnVal = strings.Replace(returnVal, prevString+" "+v, prevString+" "+val, -1)
					}
				}

			} else {
				if strings.Contains(v, ";"){
					v = strings.Replace(v, ";","", -1)
				}
				v = strings.Replace(v, ".", "", -1)
				if prevString=="mailbox"{
					//fmt.Println(v)
					if strings.Contains(v, ":"){
						v = strings.Replace(v, ":","",-1)
					}
				}
				if _, err := strconv.Atoi(v); err == nil {
					if val, ok := SanitizeMapper[strings.Replace(prevString, ":","",-1)]; ok {
						returnVal = strings.Replace(returnVal, prevString+" "+v, prevString+" "+val, -1)
					}
				}
			}

		} else {

			if _, err := strconv.Atoi(v); err == nil {
				if val, ok := SanitizeMapper[prevString]; ok {
					returnVal = strings.Replace(returnVal, prevString+" "+v, prevString+" "+val, -1)

				}
			}
		}

		prevString = v
	}
	return returnVal
}

func HandleCustomOverride(bts []byte) string {
	return ""
}

func UpdateSeverityCounters(bts []byte) {

	stringArray := strings.Split(string(bts), " ")
	var messageData string
	var component string
	if len(stringArray)==3{
		return
	}
	if stringArray[3] == "" {
		component = stringArray[4]
	} else {
		component = stringArray[3]
	}
	component = strings.Replace(component, "[", "", -1)
	component = strings.Replace(component, "]", "", -1)
	component = strings.Split(component, "-")[0]
	if strings.Contains(component, "qtp") {
		component = "qtp"
	}
	severity := stringArray[2]
	if bytes.Contains(bts, []byte("Finished moving blobs for ")){
		messageData = "Finished moving blobs for {item count} items in mailbox {mailbox id} to volume {volume id}."
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("Number of blobs to backup for mailbox")){
		messageData = "Number of blobs to backup for mailbox {mailbox id}: {blob count}"
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("Moving blobs for ")){
		messageData = "Moving blobs for {blob count} items in mailbox {mailbox id} to volume {volume id}."
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("Skipping the recently modified/moved folder")){
		messageData = "Skipping the recently modified/moved folder {folder path}"
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("deleting folder")){
		messageData = "deleting folder {folder path}"
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("problem marking message as read (ignored):")){
		messageData = "problem marking message as read (ignored): {item id}"
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("MIME handler com.zimbra.cs.mime.handler.ConverterHandler for ")){
		messageData = "MIME handler com.zimbra.cs.mime.handler.ConverterHandler for {extension} ({MIME type}) not found."
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("Unable to index: ")){
		messageData = "Unable to index: {invalid header (harmless)}"
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("search is: ")){
		messageData = "search is: {search query}"
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("OpenLuceneIndex impl=NIOFSDirectory,dir=")){
		messageData = "OpenLuceneIndex impl=NIOFSDirectory,dir={path to index files}"
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("POP3 client identified as:")){
		messageData = "POP3 client identified as: {ip address}"
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("mailop - Deleting Message (id=")){
		messageData = "mailop - Deleting Message (id={item id (...)})"
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("Batch complete processed=")){
		messageData = "Batch complete processed={total},failed={failed},elapsed={time ms} ({count} items/sec)"
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("selected folder ")){
		messageData = "selected folder {folder name}"
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("copying message data from existing session:")){
		messageData = "copying message data from existing session: {folder path}"
		ProcessUpdateMetric(component, messageData, severity)
		return

	}
	if bytes.Contains(bts, []byte("copying message data from serialized session:")){
		messageData = "copying message data from serialized session: {folder path}"
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("CREATE failed: mailbox already exists: ")){
		messageData = "CREATE failed: mailbox already exists: {item}"
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if bytes.Contains(bts, []byte("DavServlet operation PROPFIND to")){
		messageData = "DavServlet operation PROPFIND to {email} {folder path} (depth: zero) finished in {time}ms"
		ProcessUpdateMetric(component, messageData, severity)
		return
	}
	if strings.Contains(string(bts), " [] ") {
		if strings.Contains(string(bts), "/proxy/chord/"){
			original := strings.Split(string(bts)," - ")
			comp := strings.Split(original[1], " ")
			messageData = comp[0]+" - http://{proxy URL} service_id={code},x"
			ProcessUpdateMetric(component, messageData, severity)
			return
		}
		if strings.Contains(string(bts), "Slow execution ") {
			messageData = "Slow execution ({query time}ms): {query}"
			ProcessUpdateMetric(component, messageData, severity)
			return
		}
		messageData = strings.Split(string(bts), " [] ")[1]
		if strings.Contains(strings.ToLower(messageData), "@") {
			if strings.Contains(messageData, "nginxlookup - user not found:") {
				messageData = "nginxlookup - user not found: {email}"
			} else if strings.Contains(messageData, "misc - Sent SpamReport") {
				messageData = "misc - Sent SpamReport{account={email}}, mbox={id}, msgId={id}}, isSpam={bool}, origIp=null, action=imap copy, srcFolder=/{Folder name}, destFolder=/{Folder name}, destAccount=null, reportRecipient={email}}"
			}

			ProcessUpdateMetric(component, messageData, severity)
			return
		} else if strings.Contains(messageData, "initializing folder and tag caches for mailbox ") {
			messageData = "initializing folder and tag caches for mailbox {id}"
			ProcessUpdateMetric(component, messageData, severity)
			return
		} else if strings.Contains(messageData, " idle sessions (SOAP). ") {
			messageData = "SessionCache - Removed {number} idle sessions (SOAP). {number} active sessions remain."

			ProcessUpdateMetric(component, messageData, severity)
			return
		}
		if strings.Contains(string(bts), "Finished backing up") {
			messageData = "Finished backing up {count} of {total} accounts"
			ProcessUpdateMetric(component, messageData, severity)
			return
		}
		if strings.Contains(string(bts), "imap - dropping connection for user "){
			messageData = "imap - dropping connection for user {username} ({reason})"
			ProcessUpdateMetric(component, messageData, severity)
			return
		}
		ProcessUpdateMetric(component, messageData, severity)
	} else {
		bts = bytes.Replace(bts, []byte(";ua=ZimbraWebClient - "), []byte(";ua=ZimbraWebClient_-_"), -1)
		lineArray := strings.Split(string(bts), " - ")
		if len(lineArray)==1{
			return
		}
		if strings.Contains(string(bts), "/proxy/chord/"){
			firstPart := strings.Split(lineArray[1], " ")
			messageData = firstPart[0]+" http://{http store host}:{port}/{path to locator} service_id={code},{bytes}"
			ProcessUpdateMetric(component, messageData, severity)
			return
		}
		messageData = repNums(lineArray[1], bts)
		if strings.Contains(string(bts), "Finished backing up") {
			messageData = "Finished backing up {count} of {total} accounts"
			ProcessUpdateMetric(component, messageData, severity)
			return
		}
		if strings.Contains(string(bts), "imap - dropping connection for user "){
			messageData = "imap - dropping connection for user {username} ({reason})"
			ProcessUpdateMetric(component, messageData, severity)
			return
		}
		if strings.Contains(string(bts), "no such folder: "){
			original := strings.Split(messageData, "no such folder: ")
			messageData = original[0]+" {folder path}"
			ProcessUpdateMetric(component, messageData, severity)
			return
		}

		ProcessUpdateMetric(component, messageData, severity)
	}

}

func ProcessUpdateMetric(component string, target string, severity string) {

	thisThing := strings.Replace(component, "[", "", -1)
	thisThing = strings.Replace(thisThing, "]", "", -1)
	thisThing = severity + "|ZMD|" + strings.Split(component, "-")[0] + "|ZMD|" + target

	AllDetailMapper.Update(thisThing, func(old interface{}) interface{} {
		v, _ := old.(int)
		return v + 1
	})
}

func CalculatePercentages(cMap *cmap.CMap) string {
	keys := cMap.Keys()
	total := 0
	TmpMapper := make(map[string]int)
	keys2 := make([]string, 0, len(TmpMapper))
	for _, v := range keys {
		total = total + cMap.Get(v).(int)
		componentArray := strings.Split(v.(string), "|ZMD|")
		component := componentArray[1]
		if _, ok := TmpMapper[component]; ok {
			TmpMapper[component] = TmpMapper[component] + cMap.Get(v).(int)
		} else {
			TmpMapper[component] = cMap.Get(v).(int)
		}
	}
	for key := range TmpMapper {
		keys2 = append(keys2, key)
	}
	stringBuilder := ""
	sort.Strings(keys2)
	for _, v := range keys2 {
		thisPercentage := TmpMapper[v] * 100
		thisPercentage = thisPercentage / total
		stringBuilder += "[" + v + ": " + strconv.Itoa(thisPercentage) + "%] "

	}
	return stringBuilder
}
