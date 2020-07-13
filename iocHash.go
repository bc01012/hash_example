package main

import (
	"compress/gzip"
	"database/sql"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
	//"github.com///myPkg"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
)

var mux sync.Mutex
var wg sync.WaitGroup

var (
	id          int
	id1         int
	md5         string
	antivirus   sql.NullString
	result      sql.NullString
	description sql.NullString
	counter     int
	confidence  sql.NullString
	source      sql.NullString
	threat      sql.NullString
	ip          string
	ip1         string
	org         sql.NullString
	category    string
	hash        string
	countROW    int
)

//db info
var db5 = &sql.DB{}
var dbType = "mysql"
var dbUserName = "root"
var dbTableName = "bcapi"
var dbPassword = "022300U"
var dbIpAndPort = "172.23.100.8:3306"

var checkUnverifiedTimeWait = 1 //minutes ,to check whether we have new tasks or not
var excuName = "iocHash"        //name of this program...
var queryFromHash = "SELECT md5 FROM ioc_hash WHERE 1<>2  AND TO_DAYS(NOW()) - TO_DAYS(create_date) <= 180 order by modify_date asc"
var queryHashMD5 = "select md5 from ioc_hash where  md5=?"
var updateIOCHash = "Update ioc_hash set vt_positives=?,bci_scores=?,most_possible_filename=?,vt_signers=?,modify_date=? where  md5=?"
var insertIOCHash = "insert into ioc_hash (md5,vt_positives,bci_scores,most_possible_filename,vt_signers,create_date,modify_date) values(?,?,?,?,?,?,?)"
var selectSyncTaskTime = "select MAX(triggered_time) from sync_trigger_detail where task_name=?"
var getMaxTriggeredTime = "SELECT MAX(triggered_time) FROM sync_trigger_detail WHERE task_name=?"

var taskNameRefreshHash = "iocHashRefresh" //refresh sync task name
var layout = "2006-01-02 15:04:05"         //time format
var deadSingal = 0                         //whether db dead or not

var maxAPIKeyUser = 103        // all keys we have +1
var user = 1                   //start from no. key
var count = 0                  //counter of record processed
var beDayHour = 720            //evry 30 days,now time delete this hour...
var checkRefreshTimeWait = 720 //how long you should wait then check whether its time to refresh
var highScore = 5              //score for high confidence virus detect engine
var midScore = 3               //score for medium confidence virus detect engine
var lowScore = 1               //score for low confidence virus detect engine
var reCAPTCHAsignal = 0        //whether our ip is block by VirusTotal or not
var dailyKeyCount = 0          //the amount how many keys, dead today,update to 0 every 00:00 UTC
var debugFlag bool = false     //control to print or not...
var secondsWaitDBDead = 14400  //after 4 hr,db shouldve reconnected...

type AHashRecord struct { //data to insert into a hash record....
	list_md5         string
	list_posScore    int
	list_bciScore    int
	list_fname       string
	list_signers     string
	list_takID       int
	list_vt_total    int
	list_id          int
	list_vt_lastseen string
}

func init() {
	//evrytime process up,fit in the db info at first,but not connect until we ping
	dbConnect(dbType, dbUserName, dbPassword, dbIpAndPort, dbTableName)
}
func main() {
	//lock and wait, this never end since never been done
	wg.Add(10)
	mux.Lock()
	go stillAlive()  //run every min,refresh config file and so on
	go anyTaskToDo() //run every min,check whether we have task to do...
	go refreshHash() //run every 720 hours
	mux.Unlock()
	wg.Wait()
}
func CheckLY() {
	rows2, err2 := db5.Query("SELECT task_id FROM ioc_task_management WHERE type='hash' and  STATUS !=2  AND SOURCE = 'LY' OR type='hash' and  STATUS !=2  AND SOURCE = 'CWB' OR type='hash' and  STATUS !=2  AND SOURCE = 'SINICA';")
	if err2 != nil {
		log.Println(err2)
	}
	var taskId int
	for rows2.Next() {
		err2 := rows2.Scan(&taskId)
		if err2 != nil {
			log.Println(err2)
		}
		if debugFlag {
			fmt.Println("anything", taskId)
			fmt.Println("################################")
		}
		DealingUnverifiedThreat(taskId)
	}
	if debugFlag {
		fmt.Println("ly,cwb,sinica check done")
	}
}

func anyTaskToDo() {
	CheckLY()
	rows, err := db5.Query("SELECT count(*) FROM ioc_task_management WHERE type='hash' and  STATUS = 0 ;")
	if err != nil {
		log.Println(err)
	}
	var gg int
	defer func() {
		if err := recover(); err != nil {
			if debugFlag {
				fmt.Println("any task lost connect...")
			}
			log.Println(err)
			deadSingal = 1
		} else {
			defer rows.Close()
			deadSingal = 0
			if debugFlag {
				fmt.Println("safe here")
			}
		}
	}()
	for rows.Next() {
		err := rows.Scan(&gg)
		if err != nil {
			log.Println(err)
		}
		if gg > 0 {
			if debugFlag {
				fmt.Println("we have tasks...")
			}
			CheckIOCTaskManagement()
		} else {
			if debugFlag {
				fmt.Println("no tasks to do...")
			}
		}
	}
	time.AfterFunc(time.Duration(checkUnverifiedTimeWait)*time.Minute, anyTaskToDo)
}
func CheckIOCTaskManagement() {
	rows, err := db5.Query("SELECT task_id FROM ioc_task_management WHERE type='hash'  and status =0  order by created_date desc limit 1;") //and task_id =
	if err != nil {
		log.Println(err)
	}
	var taskId int
	for rows.Next() {
		err := rows.Scan(&taskId)
		if err != nil {
			log.Println(err)
		}
		if debugFlag {
			fmt.Println("anything", taskId)
		}
		DealingUnverifiedThreat(taskId)
	}
}
func UpdateIOCTaskManagement(tkID int, statusOfit int) {
	if debugFlag {
		fmt.Println("&&&", tkID, statusOfit)
	}
	if statusOfit == 2 {
		tx, _ := db5.Begin()
		t := time.Now()
		tx.Exec("UPDATE  ioc_task_management set status=?,complete_date=? where task_id=? ", statusOfit, t.Format(layout), tkID)
		tx.Commit()
	} else {
		tx, _ := db5.Begin()
		tx.Exec("UPDATE ioc_task_management set status=? where task_id=?", statusOfit, tkID)
		tx.Commit()
	}
}

func DealingUnverifiedThreat(tkID int) {
	t1 := time.Now()
	var nameOgLog = "hashErrorLog_" + t1.Format("2006-01-02 15-04-05") + ".log"
	logInit(nameOgLog)
	log.Println("value", "|", "description", "|", "startTime", "|", "endTime", "|", "timeSpent(ms)")
	tkid := strconv.Itoa(tkID)
	var getUnverifiedStatusOneByTaskID = "select value,id from ioc_unverified_threat where task_id=" + tkid //+ " and status=1 limit " + limit
	UpdateIOCTaskManagement(tkID, 1)
	rows2, err2 := db5.Query(getUnverifiedStatusOneByTaskID)
	if err2 != nil {
		log.Println("db err")
	}
	var howManyUnverified = 0
	var howManyAlreadyExisted = 0
	var howManyinserted = 0
	var howManyUnknownError = 0

	defer func() {
		if err := recover(); err != nil {
			if debugFlag {
				fmt.Println(err)
			}
			log.Println(err)
			log.Println("task_id", tkid, "encountering connecting error")
			log.Println("total number :", howManyUnverified)
			done := howManyAlreadyExisted + howManyinserted + howManyUnknownError
			undone := howManyUnverified - done
			log.Println("finished number :", done)
			log.Println("unfinished number :", undone)
			UpdateIOCTaskManagement(tkID, 0)
			// don := strconv.Itoa(done)
			// udon := strconv.Itoa(undone)
			//myPkg.MailingAMsg("task_id:" + tkid + " encountering connecting error.\n" + "done:" + don + "undone:" + udon)
		} else {
			rows2.Close()
		}
	}()
	aString := ArrayOFHashUnder()
	var toDoHashList []AHashRecord

	for rows2.Next() {
		howManyUnverified = howManyUnverified + 1
		err2 := rows2.Scan(&hash, &id)
		if err2 != nil {
			log.Println(err2)
		}
		tstart := time.Now()
		if debugFlag {
			fmt.Println("dealing...", tkID, " num：", howManyUnverified, "  ", hash)
		}
		if howManyUnverified%10 == 0 {
			tx, _ := db5.Begin()
			tx.Exec("UPDATE ioc_task_management set result_records=? where task_id=?", howManyUnverified, tkID)
			tx.Commit()
			if CheckTaskPause(tkID) {
				t := time.Now()
				log.Println(tkID, " pause at", t.Format(layout))
				break
			}
		}
		if CanWePassThisHash(hash, aString) {
			howManyAlreadyExisted = howManyAlreadyExisted + 1
			tDone := time.Now()
			tus := time.Since(tstart)
			log.Println(hash, "|", " already existed", "|", tstart.Format(layout), "|", tDone.Format(layout), "|", tus.Milliseconds())
			if debugFlag {
				fmt.Println(hash, "|", " already existed", "|", tstart.Format(layout), "|", tDone.Format(layout), "|", tus.Milliseconds())
			}
			mappingIOCTask(hash, tkID, id)
		} else {
			VTmd5, VT_posi, VT_bciscore, posifilename, VTsigner, vt_total, vt_lastseen := downloadVT2(hash)
			if len(VTmd5) == 32 {
				howManyinserted = howManyinserted + 1
				var aRec = AHashRecord{list_md5: VTmd5,
					list_posScore:    VT_posi,
					list_bciScore:    VT_bciscore,
					list_fname:       posifilename,
					list_signers:     VTsigner,
					list_takID:       tkID,
					list_vt_total:    vt_total,
					list_id:          id,
					list_vt_lastseen: vt_lastseen}
				toDoHashList = append(toDoHashList, aRec)
				tDone := time.Now()
				tus := time.Since(tstart)
				log.Println(hash, "|", " new insert", "|", tstart.Format(layout), "|", tDone.Format(layout), "|", tus.Milliseconds())
				if debugFlag {
					fmt.Println(hash, "|", " new insert", "|", tstart.Format(layout), "|", tDone.Format(layout), "|", tus.Milliseconds())
				}

			} else {
				howManyUnknownError = howManyUnknownError + 1
				var aRec = AHashRecord{list_md5: hash,
					list_posScore:    -1,
					list_bciScore:    0,
					list_fname:       "",
					list_signers:     "",
					list_takID:       tkID,
					list_vt_total:    0,
					list_id:          id,
					list_vt_lastseen: vt_lastseen}
				toDoHashList = append(toDoHashList, aRec)
				tDone := time.Now()
				tus := time.Since(tstart)
				log.Println(hash, "|", " not found but still insert", "|", tstart.Format(layout), "|", tDone.Format(layout), "|", tus.Milliseconds())
				if debugFlag {
					fmt.Println(hash, "|", " not found but still insert", "|", tstart.Format(layout), "|", tDone.Format(layout), "|", tus.Milliseconds())
				}
			}
		}

		tused := time.Since(tstart)
		if debugFlag {
			fmt.Println("tused: ", tused)
		}
	}
	InsertIOCHashData(toDoHashList)

	// elapsed := time.Since(t1)
	// t2 := time.Now()
	// //var timeUsedChecking = t2.Sub(t1).String()
	// t := time.Now()
	// var t2f = //myPkg.FmtDuration(time.Since(t1))
	// if debugFlag {
	// 	fmt.Println("elapsed: ", elapsed)
	// 	fmt.Println(t2.Sub(t1).String())
	// 	fmt.Println(t.Format(layout), "done unverifiedThreat Hash checking...where unverified count this round=", howManyUnverified)
	// }
	// if howManyUnverified > 0 {
	//
	// 	leftnumber := checkIocTaskLeft()
	// 	tt64 := int64(howManyUnverified)
	// 	te64 := int64(howManyAlreadyExisted)
	// 	ti64 := int64(howManyinserted)
	// 	tu64 := int64(howManyUnknownError)
	// 	ln64 := int64(leftnumber)
	//
	// 	ttadc := //myPkg.AddComma(tt64)
	// 	teadc := //myPkg.AddComma(te64)
	// 	tiadc := //myPkg.AddComma(ti64)
	// 	tuadc := //myPkg.AddComma(tu64)
	// 	lnadc := //myPkg.AddComma(ln64)
	//
	// 	t := time.Now() //.String()
	// 	tfm := t.Format("2006-01-02 15:04:05")
	//
	// 	MailContentInKeyAndValue := mailKeyValueContent(TitleAndContent{"服務名稱", excuName + " 任務ID " + tkid, "center"},
	// 		TitleAndContent{"資料庫剩餘未處理數量", lnadc, "right"},
	// 		TitleAndContent{"本次處理總數量", ttadc, "right"},
	// 		TitleAndContent{"本次處理已存在情資資料庫數量", teadc, "right"},
	// 		TitleAndContent{"本次處理新增情資數量", tiadc, "right"},
	// 		TitleAndContent{"本次處理略過數量", tuadc, "right"},
	// 		TitleAndContent{"本次處理花費時間", t2f, "left"},
	// 		TitleAndContent{"Timestamp", tfm, "left"})
	// 	tx, _ := db5.Begin()
	// 	tx.Exec("update ioc_task_management set result_records=?,added_records=?,failed_records=? where task_id = ?", howManyUnverified, howManyinserted, howManyUnknownError, tkid)
	// 	tx.Commit()
	// 	//myPkg.MailingHtmlAndFileName(MailContentInKeyAndValue, nameOgLog)
	// }

	defer func() {

		if err := recover(); err != nil {
			if debugFlag {
				fmt.Println(err)
			}
			log.Println(err)
			log.Println("task_id", tkid, "encountering connecting error")
			log.Println("total number :", howManyUnverified)
			done := howManyAlreadyExisted + howManyinserted + howManyUnknownError
			undone := howManyUnverified - done
			log.Println("finished number :", done)
			log.Println("unfinished number :", undone)
			UpdateIOCTaskManagement(tkID, 0)
			// don := strconv.Itoa(done)
			// udon := strconv.Itoa(undone)
			//myPkg.MailingAMsg("task_id:" + tkid + " encountering connecting error.\n" + "done:" + don + "undone:" + udon)
		} else {
			UpdateIOCTaskManagement(tkID, 2)
			if howManyUnverified != GetTaskCount(tkID) {
				//myPkg.MailingAMsg("task_id:" + tkid + " escaping error...")
			}
		}
	}()
}

type TitleAndContent struct {
	title, content, alignWhere string
}

func mailKeyValueContent(args ...TitleAndContent) (a string) {
	var ss string
	for i := 0; i < len(args); i++ {
		if i%2 == 0 {
			ss = ss + `<tr class="even"><td class="title">` + args[i].title + `:</td><td class="content";style="text-align:` + args[i].alignWhere + `";>` + args[i].content + `</td></tr>`
		} else {
			ss = ss + `<tr class="odd"><td class="title">` + args[i].title + `:</td><td class="content";style="text-align:` + args[i].alignWhere + `";>` + args[i].content + `</td></tr>`
		}
	}
	return ss
}
func GetTaskCount(aTaskID int) (taskCount int) {
	var totalCountFromATask int
	err := db5.QueryRow("select count(*) from ioc_unverified_threat where task_id = ?", aTaskID).Scan(&totalCountFromATask)
	if err != nil {
		log.Println(err)
		return 0
	}
	taskCount = totalCountFromATask
	return taskCount
}
func CheckTaskPause(tkID int) bool {
	rows, err := db5.Query("SELECT status from ioc_task_management where task_id = ?;", tkID) // SELECT md5 FROM ioc_hash WHERE  TO_DAYS(NOW()) - TO_DAYS(modify_date) <= 14
	if err != nil {
		log.Println(err)
	}
	var sss int
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(sss)
		if err != nil {
			log.Println(err)
		}
		if debugFlag {
			fmt.Println(tkID, "STATUS", sss)
		}
	}
	if sss == 3 {
		return true
	} else {
		return false
	}

}

func CanWePassThisHash(hashMD5 string, a string) bool {
	if strings.Contains(a, strings.ReplaceAll(hashMD5, " ", "")) {
		return true
	} else {
		return false
	}
}
func ArrayOFHashUnder() (a string) {
	rows, err := db5.Query("SELECT DISTINCT md5 FROM ioc_hash;") // SELECT md5 FROM ioc_hash WHERE  TO_DAYS(NOW()) - TO_DAYS(modify_date) <= 14

	if err != nil {
		log.Println("array db err")
		log.Fatal(err)
	}
	var gg string
	var totalString string
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&gg)
		if err != nil {
		}
		totalString = totalString + gg
	}
	return totalString
}

func GetIOCMD5ID(VTmd5 string) (a int) {
	var md5id int
	row, err := db5.Query("select id from ioc_hash where md5=?", VTmd5)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		defer row.Close()
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	for row.Next() {
		err1 := row.Scan(&md5id)
		if err1 != nil {
			log.Println(err1)
		}
		return md5id
	}
	return
}

var ggUser [103]int

func downloadVT2(hash string) (VTmd5 string, VT_posi int, VT_bciscore int, posifilename string, VTsigner string, vt_total int, vt_lastseen string) {

	if dailyKeyCount == maxAPIKeyUser {
		if debugFlag {
			fmt.Println("doing nothing because all the keys are expired today.. not untill 00:00 UTC")
		}
		DayKeyQoutaReached()
		return
	}
	if user >= maxAPIKeyUser {
		if debugFlag {
			fmt.Println("reachMaxAPIkey,wait 20s")
		}
		user = 1
		time.Sleep(20 * time.Second)
	}
	if ggUser[user] == 1 {
		if debugFlag {
			fmt.Println("user no.", user, " is gg，gonna skip....")
		}

		user = user + 1
		downloadVT2(hash)
		return
	} else {
		status, endDay, _, _ := headCheck(Authorization(user))
		if status == 1 {
			if debugFlag {
				fmt.Println("endOFthisKey", Authorization(user))
			}
			if endDay == 1 {
				dailyKeyCount = dailyKeyCount + 1
				if debugFlag {
					fmt.Println("a key has come to the end og the day... user no.", user, dailyKeyCount)
				}

				ggUser[user] = 1
			}
			user = user + 1
			downloadVT2(hash)
			return
		}
	}

	search := "https://www.virustotal.com/api/v3/files/" + hash
	req, err := http.NewRequest("GET", search, nil)
	req.Header.Set("x-apikey", Authorization(user))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()
	var reader io.ReadCloser
	if resp != nil {
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			reader, err = gzip.NewReader(resp.Body)
			defer reader.Close()
		default:
			reader = resp.Body
		}
		bodybyte, _ := ioutil.ReadAll(reader)
		s := string(bodybyte[:])
		//fmt.Println(s)
		if strings.Contains(s, "recaptcha") {
			if debugFlag {
				fmt.Println("recaptcha!!!!!!!!!!!")
			}
			log.Println("recaptcha when using key no.", user, " ", Authorization(user))
			DayKeyQoutaReached()
			return
		}
		if strings.Contains(s, "NotFoundError") {
			if debugFlag {
				fmt.Println("error!!!!!!!!!!!")
			}
			return
		}
		if s == "" {
			//myPkg.MailingAMsg(excuName + " " + "query limit" + //myPkg.Authorization(user))
			user = user + 1
			if debugFlag {
				fmt.Println("api key query limit..")
			}
			downloadVT2(hash)
			return
		}

		md5 := gjson.Get(s, "data.attributes.md5")
		sha1 := gjson.Get(s, "data.attributes.sha1")
		sha256 := gjson.Get(s, "data.attributes.sha256")
		positives := gjson.Get(s, "data.attributes.positives")
		names := gjson.Get(s, "data.attributes.names")
		rep := gjson.Get(s, "data.attributes.last_analysis_stats")
		proc := gjson.Get(s, "data.attributes.signature_info.signers")
		var scoreFive = "TrendMicro,Symantec,CrowdStrike,Comodo,Kaspersky,McAfee,Sophos,Fortinet"
		var scoreThree = "ClamAV,TheHacker,AVware,AVG,Avast,ESET-NOD32,BitDefender,Paloalto"
		scans := gjson.Get(s, "data.attributes.last_analysis_results")
		var bciSCORE int
		scans.ForEach(func(key, value gjson.Result) bool {
			isDetected := gjson.Get(value.String(), "category")
			if isDetected.String() == "malicious" {
				if strings.Contains(scoreFive, key.String()) {
					bciSCORE = bciSCORE + 5
				} else if strings.Contains(scoreThree, key.String()) {
					bciSCORE = bciSCORE + 3
				} else {
					bciSCORE = bciSCORE + 1
				}
			}
			return true
		})
		var fulcat string
		names.ForEach(func(key, value gjson.Result) bool {
			fulcat = fulcat + strings.ReplaceAll(value.String(), "/", "") + ", "
			return true
		})
		//fulcat = TrimSuffix(fulcat, ",")
		nm := strings.Split(fulcat, ",")
		name := nm[0]
		var mali string
		var mother int
		rep.ForEach(func(key, value gjson.Result) bool {
			if key.String() == "malicious" {
				mali = value.String()
			} else {
				if key.String() != "type-unsupported" {
					mother = mother + intBack(value.String())
				}
			}
			return true
		})
		posc, err := strconv.Atoi(mali)
		if err != nil {
			posc = 0
		}
		mother = mother + posc
		//AddMother(mother,md5.Str)
		lastSeen := gjson.Get(s, "data.attributes.last_analysis_date")
		ssg := fmt.Sprintf("%.0f", lastSeen.Num)
		var layout = "2006-01-02 15:04:05"
		i, err := strconv.ParseInt(ssg, 10, 64)
		if err != nil {
			panic(err)
		}
		atm := time.Unix(i, 0)

		if debugFlag {
			fmt.Println("#################################################################")
			fmt.Println("md5 ", md5.Str)
			fmt.Println("sha1 ", sha1.Str)
			fmt.Println("sha256 ", sha256.Str)
			fmt.Println("positives ", positives.Num)
			fmt.Println("names ", name)
			fmt.Println("vt_score ", posc)
			fmt.Println("mother ", mother)
			fmt.Println("proc ", proc.Str)
			fmt.Println("bciSCORE ", bciSCORE)
			fmt.Println("last update：", atm.Format(layout))
			fmt.Println("#################################################################")
		}
		user = user + 1
		return md5.Str, posc, bciSCORE, name, proc.Str, mother, atm.Format(layout)
	}
	user = user + 1
	return
}
func intBack(numString string) (a int) {
	toInt, err := strconv.Atoi(numString)
	if err != nil {
		toInt = 0
	}
	return toInt
}
func AddMother(mother int, hh string) {
	tx, _ := db5.Begin()
	tx.Exec("UPDATE  ioc_hash set vt_total=?  where md5=? ", mother, hh)
	tx.Commit()
}
func AddLastSeen(vt_lastseen string, hh string) {
	tx, _ := db5.Begin()
	tx.Exec("UPDATE  ioc_hash set vt_lastseen=?  where md5=? ", vt_lastseen, hh)
	tx.Commit()
}

func refreshHash() {
	t1 := time.Now()
	if timeToRefresh(taskNameRefreshHash) {
		fmt.Println("it's time")
		rows, err := db5.Query(queryFromHash) //
		if err != nil {
			log.Println(err)
		}
		defer func() {
			defer rows.Close()
			if err := recover(); err != nil {
				log.Println(err)
			}
		}()
		for rows.Next() {
			err := rows.Scan(&hash)
			if err != nil {
				log.Println(err)
			}
			if debugFlag {
				fmt.Println("dealing...", count)
			}

			tu := time.Now()
			VTmd5, VT_posi, VT_bciscore, posifilename, VTsigner, vt_total, vt_lastseen := downloadVT2(hash)
			if len(VTmd5) == 32 {
				RefreshIOCHashData(VTmd5, VT_posi, VT_bciscore, posifilename, VTsigner, vt_total, vt_lastseen)
			}
			count = count + 1
			timeSpent := time.Since(tu)
			if debugFlag {
				fmt.Println("timeSpent osint: ", timeSpent)
			}

		}
		timeRefresh := time.Now()
		syncTask(taskNameRefreshHash, timeRefresh.Format(layout))
		t2 := time.Now()
		fmt.Println(t2.Sub(t1).String())
		//var timeUsedChecking = t2.Sub(t1).String()
		//myPkg.MailingAMsg("\"log_type\":\"log\"\n\"serviceName\":\"" + excuName + "\"\n\"msg\":\"done refreshing\"\n\"timeUsedChecking\":\"" + timeUsedChecking + "\"")
	} else {
		if debugFlag {
			fmt.Println("Refresh：not the date and time...", t1.Format(layout))
		}
	}
	time.AfterFunc(time.Duration(checkRefreshTimeWait)*time.Hour, refreshHash)
}

func logInit(logPath string) {
	f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
	}
	//defer f.Close()
	log.SetOutput(f)
	log.SetFlags(0)
}

func SaveThem(logPath string, writeSomething string) {
	f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
	}
	defer f.Close()
	log.SetOutput(f)
	log.SetFlags(0)
	log.Println(writeSomething)
}

var counterVT = 1
var maxCounter = 1

func headCheck(apiKey string) (status, endDay, endHour, endMonth int) {
	status = 0
	endDay = 0
	endHour = 0
	endMonth = 0
	search := "https://www.virustotal.com/api/v3/users/" + apiKey
	req, err := http.NewRequest("GET", search, nil)
	req.Header.Set("x-apikey", apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()
	var reader io.ReadCloser
	if resp != nil {
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			reader, err = gzip.NewReader(resp.Body)
			defer reader.Close()
		default:
			reader = resp.Body
		}
		bodybyte, _ := ioutil.ReadAll(reader)
		s := string(bodybyte[:])
		//fmt.Println(s)
		dayReqLimit := gjson.Get(s, "data.attributes.quotas.api_requests_daily.allowed")
		dayReqUsed := gjson.Get(s, "data.attributes.quotas.api_requests_daily.used")
		hourReqLimit := gjson.Get(s, "data.attributes.quotas.api_requests_hourly.allowed")
		hourReqUsed := gjson.Get(s, "data.attributes.quotas.api_requests_hourly.used")
		monthReqLimit := gjson.Get(s, "data.attributes.quotas.api_requests_monthly.allowed")
		monthReqUsed := gjson.Get(s, "data.attributes.quotas.api_requests_monthly.used")
		if dayReqLimit.Num <= dayReqUsed.Num {
			if debugFlag {
				fmt.Println("overuse day", dayReqLimit.Num, dayReqUsed.Num)
			}

			status = 1
			endDay = 1
		}
		if hourReqLimit.Num <= hourReqUsed.Num {
			if debugFlag {
				fmt.Println("overuse hour", hourReqLimit.Num, hourReqUsed.Num)
			}

			status = 1
			endHour = 1
		}
		if monthReqLimit.Num <= monthReqUsed.Num {
			if debugFlag {
				fmt.Println("overuse month", hourReqLimit.Num, hourReqUsed.Num)
			}

			status = 1
			endMonth = 1
		}
		return status, endDay, endHour, endMonth
	}
	return status, endDay, endHour, endMonth
}

func CheckAndWait(timeSecond int) {
	var g = 0
	for g < timeSecond {
		err := db5.Ping()
		if err != nil {
			g = g + 1
			time.Sleep(600 * time.Second)
		} else {
			g = timeSecond
		}
	}
}

func InsertIOCHashData(aTODOlist []AHashRecord) {
	err := db5.Ping()
	if err != nil {
		if debugFlag {
			fmt.Println("db gg")
		}
		//myPkg.MailingAMsg("db lost connection " + dbIpAndPort)
		CheckAndWait(secondsWaitDBDead)
	}
	aString := ArrayOFHashUnder()

	tx, _ := db5.Begin()
	for i := 0; i < len(aTODOlist); i++ {
		t := time.Now()
		if !CanWePassThisHash(aTODOlist[i].list_md5, aString) {
			tx.Exec("insert into ioc_hash (md5,vt_positives,bci_scores,most_possible_filename,vt_signers,create_date,modify_date) values(?,?,?,?,?,?,?)", aTODOlist[i].list_md5, aTODOlist[i].list_posScore, aTODOlist[i].list_bciScore, aTODOlist[i].list_fname, aTODOlist[i].list_signers, t.Format(layout), t.Format(layout))
			//mappingIOCTask(aTODOlist[i].list_md5,aTODOlist[i].list_takID, aTODOlist[i].list_id)
			//list_vt_lastseen: vt_lastseen,}
			if debugFlag {
				fmt.Println("inserting...", aTODOlist[i].list_md5)
			}
		}
	}
	tx.Commit()

	for i := 0; i < len(aTODOlist); i++ {
		mappingIOCTask(aTODOlist[i].list_md5, aTODOlist[i].list_takID, aTODOlist[i].list_id)
	}

}
func RefreshIOCHashData(md5 string, posScore int, bciScore int, fname string, signers string, vt_total int, vt_lastseen string) {

	if checkHashMD5(md5) {
		tx, _ := db5.Begin()
		t := time.Now()
		tx.Exec(updateIOCHash, posScore, bciScore, fname, signers, t.Format(layout), md5)
		tx.Commit()
		AddMother(vt_total, md5)
		//AddLastSeen(vt_lastseen, md5)
	} else {
		tx, _ := db5.Begin()
		t := time.Now()
		tx.Exec(insertIOCHash, md5, posScore, bciScore, fname, signers, t.Format(layout), t.Format(layout))
		tx.Commit()
		AddMother(vt_total, md5)
		//AddLastSeen(vt_lastseen, md5)
	}
}

func mappingIOCTask(whatValue string, takID int, id int) {
	row, err := db5.Query("select id from ioc_hash where md5=? limit 1", whatValue)
	var itId int
	var aID = 0
	if err != nil {
	}
	defer func() {
		defer row.Close()
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	for row.Next() {
		err1 := row.Scan(&itId)
		if err1 != nil {
		}
		aID = itId
		if aID > 0 {
			var ccip = GetUnverifiedThreatConnectHost(whatValue, id)
			if debugFlag {
				fmt.Println(takID, aID, ccip)
			}

			if !checkMapIOC(takID, aID, ccip) {
				if debugFlag {
					fmt.Println("ioc mapping required")
				}

				tx, _ := db5.Begin()
				tx.Exec("insert into ioc_task_hash_mapping (task_id,ioc_hash_id,connect_host) values(?,?,?)", takID, aID, ccip)
				tx.Commit()
			}
		}
	}
}

type IDANDMD5 struct {
	id  int
	md5 string
}

func GetAllIDandMD5() (a []IDANDMD5) {
	row, err := db5.Query("select id,md5 from ioc_hash ;")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		defer row.Close()
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	var idd int
	var md55 string
	for row.Next() {
		err1 := row.Scan(&idd, &md55)
		if err1 != nil {
			log.Println(err1)
		}
		var hh = IDANDMD5{id: idd, md5: md55}
		a = append(a, hh)
	}
	return a
}

func checkMapIOC(idOFtask, idOFioc int, ccip string) bool {
	var c1 int
	var c2 int
	var c3 string
	row, err := db5.Query("select task_id,ioc_hash_id,connect_host from ioc_task_hash_mapping where task_id=? and ioc_hash_id =? and connect_host=? ", idOFtask, idOFioc, ccip)
	if err != nil {
		log.Println(err)
	}
	defer func() {
		defer row.Close()
		if err := recover(); err != nil {
			fmt.Println(err)
		}
	}()
	for row.Next() {
		err1 := row.Scan(&c1, &c2, &c3)
		if err1 != nil {
			log.Println(err1)
		}
		return true
	}
	return false
}

func GetCategoryID(category string) (id int) {
	var cat_id int
	var cc string
	row, err := db5.Query("select id,alias from ioc_category where alias like \"%" + category + "%\"")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		defer row.Close()
		if err := recover(); err != nil {
			fmt.Println(err)
		}
	}()
	for row.Next() {
		err1 := row.Scan(&cat_id, &cc)
		if err1 != nil {
			log.Println(err1)
		}
		return cat_id
	}
	return 0
}

func GetUnverifiedThreatConnectHost(whatValue string, idOfunv int) (a string) {
	row, err := db5.Query("select connect_host from ioc_unverified_threat where value =? and id =? limit 1", whatValue, idOfunv)
	if err != nil {
	}
	var clientIP string
	var abc string
	defer func() {
		defer row.Close()
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	for row.Next() {
		err1 := row.Scan(&clientIP)
		if err1 != nil {
		}
		abc = clientIP
	}
	if debugFlag {
		fmt.Println("clientIP ", abc)
	}

	return abc
}
func GetUnverifiedThreatID(whatValue string, aTaskID int) (a int) {
	row, err := db5.Query("select id from ioc_unverified_threat where value =? and task_id =? limit 1", whatValue, aTaskID)
	var idOFunv int
	var gg int
	if err != nil {
	}
	defer func() {
		defer row.Close()
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	for row.Next() {
		err1 := row.Scan(&idOFunv)
		if err1 != nil {
		}
		gg = idOFunv
	}
	return gg
}

func checkHashMD5(hashMD5 string) bool {
	var iocHashMD5 string
	row, err := db5.Query(queryHashMD5, hashMD5)
	if err != nil {
	}
	defer func() {
		defer row.Close()
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	for row.Next() {
		err1 := row.Scan(&iocHashMD5)
		if err1 != nil {
		}
		return true
	}
	return false
}

func dbConnect(dbType, dbUserName, dbPassword, dbIpAndPort, dbTableName string) {
	db5, _ = sql.Open(dbType, dbUserName+":"+dbPassword+"@tcp("+dbIpAndPort+")/"+dbTableName)
	db5.SetMaxIdleConns(5)
	db5.SetMaxOpenConns(500000)
	db5.SetConnMaxLifetime(time.Hour)
	defer func() {
		err := db5.Ping()
		if err != nil {
			if debugFlag {
				fmt.Println("db gg")
			}
			log.Println(err)
		}
	}()
}

func iocHashUpdate(hash string) {
	tx, _ := db5.Begin()
	t := time.Now()
	tx.Exec("update ioc_hash set modify_date=? where md5=?", t.Format(layout), hash)
	tx.Commit()
}
func syncTask(taskName, triggerTime string) {
	tx, _ := db5.Begin()
	tx.Exec("insert into sync_trigger_detail (task_name,triggered_time) value(?,?)", taskName, triggerTime)
	tx.Commit()
}
func timeToRefresh(taskName string) bool {
	t := time.Now()
	beDay := t.Add(-time.Duration(beDayHour) * time.Hour)
	triTime, err := time.Parse(layout, getMaxTriggerTime(taskName))
	if err != nil {
	}
	if debugFlag {
		fmt.Println("MAX SYNC DATE:", triTime)
		fmt.Println("beforeDayDATE:", beDay)
	}
	if triTime.After(beDay) {
		return false
	}
	return true
}
func getMaxTriggerTime(taskName string) (triggerTime string) {
	var s string
	err := db5.QueryRow(getMaxTriggeredTime, taskName).Scan(&s)
	if err != nil {
		if err == sql.ErrNoRows {
		} else {
			trtr := time.Now()
			triggerTime = trtr.Format(layout)
			tx, _ := db5.Begin()
			tx.Exec("insert into sync_trigger_detail (task_name,triggered_time) value(?,?)", taskName, triggerTime)
			tx.Commit()
			return triggerTime
		}
	}
	triggerTime = s
	//fmt.Println("tri time ", triggerTime)
	return triggerTime
}
func RECSS() bool {
	var s int
	err := db5.QueryRow("SELECT COUNT(*) FROM ioc_task_management WHERE TYPE ='domain' AND STATUS = 0;").Scan(&s)
	if err != nil {
		s = 100
		return false
	}
	if s == 0 {
		return true
	}
	return false
}

func stillAlive() {

	//myPkg.ReadConfM() //read th mail config file...
	if deadSingal == 1 {
		//myPkg.MailingAMsg("db lost connection " + dbIpAndPort)
		CheckAndWait(14400)
		go Waiting()
	}

	t := time.Now()
	if debugFlag {
		fmt.Println("DEAD OR NOT ", deadSingal)
		fmt.Println(t.Format(layout), "service alive")
		fmt.Println("dailyKeyCount/max key can used ", dailyKeyCount, maxAPIKeyUser)
	}
	if t.Hour() == 8 {
		if t.Minute() == 0 {
			dailyKeyCount = 0
			for i := 0; i < len(ggUser); i++ {
				ggUser[i] = 0
			}
		}
	}
	time.AfterFunc(1*time.Minute, stillAlive)
}
func Waiting() {
	if deadSingal == 0 {
		if debugFlag {
			fmt.Println("now we safe")
		}
		go anyTaskToDo()
	} else {
		if debugFlag {
			fmt.Println("now we wait")
		}
	}
}

func checkIocTaskLeft() (a int) {
	rows, err := db5.Query("select task_id from ioc_task_management where type = 'hash' and status =0;")
	var tt string
	var ttCount int
	if err != nil {
		log.Println(err)
	}
	defer func() {
		defer rows.Close()
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	for rows.Next() {
		err := rows.Scan(&tt)
		if err != nil {
			log.Println(excuName + " db error")
		}
		var qq = "select count(*) from ioc_unverified_threat where task_id=" + tt + " ;"
		ttCount = ttCount + CollectIocTaskLeft(qq)
	}
	return ttCount
}
func CollectIocTaskLeft(qq string) (a int) {
	rows, err := db5.Query(qq)
	if err != nil {
		log.Println(err)
	}
	var ggg int
	defer func() {
		defer rows.Close()
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	for rows.Next() {
		err := rows.Scan(&ggg)
		if err != nil {
		}
		return ggg
	}
	return 0
}

func DayKeyQoutaReached() {
	timestamp := time.Now()
	t2 := timestamp.AddDate(0, 0, 1)
	str := t2.Format("2006-01-02") + " 00:08:00"
	t, err := time.Parse(layout, str)
	if err != nil {
		log.Println(err)
	}
	diff := t.Sub(timestamp).Seconds()
	if debugFlag {
		fmt.Println(timestamp.Format("2006-01-02 03:04:05"))
		fmt.Println(t.Format("2006-01-02 03:04:05"))
		fmt.Println("seconds you should wait...", diff)
	}
	time.Sleep(time.Second * time.Duration(300))

	var gg = 0
	for gg < 1 {
		// if //myPkg.DownloadVT("b0d1cfe9cec16368375f2390396200f5") {
		// 	time.Sleep(time.Second * time.Duration(300))
		// } else {
		gg = 1

		// }
	}
	dailyKeyCount = 0
	for i := 0; i < len(ggUser); i++ {
		ggUser[i] = 0
	}
	//time.Sleep(time.Second*time.Duration(diff))
}
