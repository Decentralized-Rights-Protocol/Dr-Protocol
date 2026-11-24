package compiler

import (
	"strings"
	"testing"
)

const validProgram = `protocol EducationAccess {
  identity student;
  right education {
    requires PoST(student, "verified");
  }
  activity learning {
    requires PoAT(student);
    reward 10 RIGHTS;
  }
  verify {
    quorum elders >= 15;
  }
}`

func TestCompileValidProgram(t *testing.T) {
	data,err:=Compile(validProgram);if err!=nil{t.Fatal(err)}
	for _,want:=range []string{`"protocol": "EducationAccess"`,`"kind": "PoST"`,`"kind": "PoAT"`,`"elder_quorum": 15`} {if !strings.Contains(string(data),want){t.Errorf("IR missing %s",want)}}
}
func TestRejectsUndeclaredIdentity(t *testing.T) {
	src:=strings.Replace(validProgram,"PoAT(student)","PoAT(ghost)",1)
	if _,err:=Compile(src);err==nil{t.Fatal("expected undeclared identity error")}
}
func TestRejectsUnsupportedRewardAsset(t *testing.T) {
	src:=strings.Replace(validProgram,"10 RIGHTS","10 BTC",1)
	if _,err:=Compile(src);err==nil{t.Fatal("expected unsupported asset error")}
}
func TestRejectsDuplicateIdentity(t *testing.T) {
	src:=strings.Replace(validProgram,"identity student;","identity student; identity student;",1)
	if _,err:=Compile(src);err==nil{t.Fatal("expected duplicate identity error")}
}
func TestRejectsMalformedSyntax(t *testing.T) {
	if _,err:=Compile("protocol broken { identity; }");err==nil{t.Fatal("expected syntax error")}
}
