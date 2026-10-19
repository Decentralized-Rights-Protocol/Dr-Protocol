package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

func main() {
	if len(os.Args) < 2 { usage(); os.Exit(2) }
	switch os.Args[1] {
	case "version":
		fmt.Printf("DRP Protocol %s\n", protocol.Version)
	case "consensus":
		if err := consensusCommand(os.Args[2:]); err != nil { fmt.Fprintln(os.Stderr,"error:",err); os.Exit(1) }
	case "chain":
		if err := chainCommand(os.Args[2:]); err != nil { fmt.Fprintln(os.Stderr,"error:",err); os.Exit(1) }
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("DRP Protocol CLI")
	fmt.Println("  drp version")
	fmt.Println("  drp consensus status [--endpoint http://localhost:8080]")
	fmt.Println("  drp consensus propose --file block.json [--endpoint http://localhost:8080]")
	fmt.Println("  drp consensus vote --file vote.json [--endpoint http://localhost:8080]")
	fmt.Println("  drp consensus commit [--endpoint http://localhost:8080]")
	fmt.Println("  drp consensus certificate <height> [--endpoint http://localhost:8080]")
	fmt.Println("  drp chain block <height> [--endpoint http://localhost:8080]")
	fmt.Println("  drp chain status [--endpoint http://localhost:8080]")
}

func consensusCommand(args []string) error {
	if len(args)==0 { return fmt.Errorf("expected status, propose, vote, commit, or certificate") }
	action := args[0]
	fs := flag.NewFlagSet("drp consensus "+action,flag.ContinueOnError)
	endpoint := fs.String("endpoint","http://localhost:8080","DRP node base URL")
	file := fs.String("file","","JSON input file for propose or vote")
	if err:=fs.Parse(args[1:]);err!=nil{return err}
	switch action {
	case "status": return requestJSON(http.MethodGet,*endpoint+"/drp/v1/consensus/status",nil)
	case "propose":
		if *file=="" { return fmt.Errorf("--file is required") }
		return postFile(*endpoint+"/drp/v1/consensus/proposals",*file)
	case "vote":
		if *file=="" { return fmt.Errorf("--file is required") }
		return postFile(*endpoint+"/drp/v1/consensus/votes",*file)
	case "commit": return requestJSON(http.MethodPost,*endpoint+"/drp/v1/consensus/commit",bytes.NewReader([]byte("{}")))
	case "certificate":
		if fs.NArg()!=1 || fs.Arg(0)=="" { return fmt.Errorf("certificate requires a block height") }
		return requestJSON(http.MethodGet,*endpoint+"/drp/v1/consensus/certificates/"+fs.Arg(0),nil)
	default: return fmt.Errorf("unknown consensus action %q",action)
	}
}

func chainCommand(args []string) error {
	if len(args)==0 { return fmt.Errorf("supported chain commands: status, block") }
	if args[0]=="status" { return consensusCommand(append([]string{"status"},args[1:]...)) }
	if args[0]=="block" {
		fs:=flag.NewFlagSet("drp chain block",flag.ContinueOnError)
		endpoint:=fs.String("endpoint","http://localhost:8080","DRP node base URL")
		if err:=fs.Parse(args[1:]);err!=nil{return err}
		if fs.NArg()!=1 { return fmt.Errorf("block requires a height") }
		return requestJSON(http.MethodGet,*endpoint+"/drp/v1/consensus/blocks/"+fs.Arg(0),nil)
	}
	return fmt.Errorf("supported chain commands: status, block")
}

func postFile(url,path string) error {
	data,err:=os.ReadFile(path);if err!=nil{return err}
	if !json.Valid(data){return fmt.Errorf("%s does not contain valid JSON",path)}
	return requestJSON(http.MethodPost,url,bytes.NewReader(data))
}

func requestJSON(method,url string,body io.Reader) error {
	url=strings.TrimRight(url,"/")
	client:=&http.Client{Timeout:15*time.Second}
	req,err:=http.NewRequest(method,url,body);if err!=nil{return err}
	req.Header.Set("Content-Type","application/json")
	resp,err:=client.Do(req);if err!=nil{return err}
	defer resp.Body.Close()
	data,err:=io.ReadAll(io.LimitReader(resp.Body,2<<20));if err!=nil{return err}
	if len(data)>0 {
		var pretty bytes.Buffer
		if json.Indent(&pretty,data,"","  ")==nil { _,_=pretty.WriteTo(os.Stdout) } else { _,_=os.Stdout.Write(data) }
		if data[len(data)-1]!='\n' { fmt.Println() }
	}
	if resp.StatusCode<200||resp.StatusCode>=300{return fmt.Errorf("node returned HTTP %s",resp.Status)}
	return nil
}
