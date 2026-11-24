package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/compiler"
)

func usage() {
	fmt.Fprintln(os.Stderr, "DRP compiler v0.1\nusage: drpc <check|compile> <file.drp> [ -o output.json ]")
}
func main() {
	if len(os.Args)<3 { usage(); os.Exit(2) }
	command,path:=os.Args[1],os.Args[2]
	if command!="check" && command!="compile" { usage(); os.Exit(2) }
	fs:=flag.NewFlagSet(command,flag.ExitOnError)
	out:=fs.String("o","","write IR to this file (compile only)")
	if err:=fs.Parse(os.Args[3:]);err!=nil{os.Exit(2)}
	source,err:=os.ReadFile(path);if err!=nil{fatal(err)}
	ir,err:=compiler.Compile(string(source));if err!=nil{fatal(err)}
	if command=="check" {fmt.Printf("DRP-Lang check passed: %s\n",path);return}
	if *out=="" {if _,err=os.Stdout.Write(append(ir,'\n'));err!=nil{fatal(err)};return}
	if err=os.WriteFile(*out,append(ir,'\n'),0644);err!=nil{fatal(err)}
	fmt.Printf("compiled %s -> %s\n",path,*out)
}
func fatal(err error){fmt.Fprintln(os.Stderr,"drpc:",err);os.Exit(1)}
