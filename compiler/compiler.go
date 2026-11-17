// Package compiler implements the first, deliberately small DRP-Lang compiler.
package compiler

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Token struct { Kind string `json:"kind"`; Value string `json:"value"`; Line int `json:"line"` }
type Requirement struct { Kind string `json:"kind"`; Subject string `json:"subject"`; Status string `json:"status,omitempty"` }
type Declaration struct { Kind string `json:"kind"`; Name string `json:"name,omitempty"`; Requires []Requirement `json:"requires,omitempty"`; Reward *int `json:"reward,omitempty"`; Asset string `json:"asset,omitempty"` }
type IR struct { Version string `json:"version"`; Protocol string `json:"protocol"`; Identities []string `json:"identities,omitempty"`; Declarations []Declaration `json:"declarations,omitempty"`; ElderQuorum int `json:"elder_quorum,omitempty"` }

var tokenPattern = regexp.MustCompile(`(?m)//[^\n]*|[A-Za-z_][A-Za-z0-9_]*|[0-9]+|"[^"\n]*"|>=|[{}();,]`)
var validToken = regexp.MustCompile(`^(//[^\n]*|[A-Za-z_][A-Za-z0-9_]*|[0-9]+|"[^"\n]*"|>=|[{}();,])$`)

func Lex(source string) ([]Token, error) {
	matches := tokenPattern.FindAllStringIndex(source, -1)
	var tokens []Token
	line := 1
	last := 0
	for _, m := range matches {
		chunk := source[last:m[0]]
		if strings.TrimSpace(chunk) != "" {
			return nil, fmt.Errorf("line %d: unexpected input %q", line+strings.Count(chunk, "\n"), strings.TrimSpace(chunk))
		}
		line += strings.Count(chunk, "\n")
		value := source[m[0]:m[1]]
		if !validToken.MatchString(value) { return nil, fmt.Errorf("line %d: invalid token %q", line, value) }
		if !strings.HasPrefix(value, "//") { tokens = append(tokens, Token{Kind: classify(value), Value: value, Line: line}) }
		line += strings.Count(value, "\n")
		last = m[1]
	}
	if rest := source[last:]; strings.TrimSpace(rest) != "" {
		return nil, fmt.Errorf("line %d: unexpected input %q", line+strings.Count(rest, "\n"), strings.TrimSpace(rest))
	}
	return tokens, nil
}
func classify(s string) string {
	if strings.HasPrefix(s, "\"") { return "string" }
	if _, err := strconv.Atoi(s); err == nil { return "number" }
	if regexp.MustCompile(`^[A-Za-z_]`).MatchString(s) { return "identifier" }
	return s
}

type parser struct { tokens []Token; pos int }
func (p *parser) peek() Token { if p.pos >= len(p.tokens) { return Token{Kind:"eof", Line:1} }; return p.tokens[p.pos] }
func (p *parser) take() Token { t:=p.peek(); if p.pos<len(p.tokens) { p.pos++ }; return t }
func (p *parser) expect(value string) (Token,error) { t:=p.take(); if t.Value!=value { return t,fmt.Errorf("line %d: expected %q, got %q",t.Line,value,t.Value) }; return t,nil }
func (p *parser) identifier() (string,error) { t:=p.take(); if t.Kind!="identifier" { return "",fmt.Errorf("line %d: expected identifier, got %q",t.Line,t.Value) }; return t.Value,nil }
func (p *parser) block() error { _,err:=p.expect("{"); return err }
func (p *parser) end() error { _,err:=p.expect(";"); return err }

func Parse(source string) (*IR,error) {
	tokens,err:=Lex(source); if err!=nil{return nil,err}
	p:=&parser{tokens:tokens}
	if _,err=p.expect("protocol"); err!=nil{return nil,err}
	name,err:=p.identifier(); if err!=nil{return nil,err}
	ir:=&IR{Version:"drp-ir/v0.1",Protocol:name}
	if err=p.block(); err!=nil{return nil,err}
	seen:=map[string]bool{}
	for p.peek().Kind!="eof" && p.peek().Value!="}" {
		switch p.peek().Value {
		case "identity":
			p.take(); id,e:=p.identifier(); if e!=nil{return nil,e}; if seen["identity:"+id] {return nil,fmt.Errorf("duplicate identity %q",id)}; seen["identity:"+id]=true
			if e=p.end(); e!=nil{return nil,e}; ir.Identities=append(ir.Identities,id)
		case "right":
			p.take(); n,e:=p.identifier(); if e!=nil{return nil,e}; if seen["right:"+n]{return nil,fmt.Errorf("duplicate right %q",n)}; seen["right:"+n]=true
			if e=p.block();e!=nil{return nil,e}; if _,e=p.expect("requires");e!=nil{return nil,e}; req,e:=parseProof(p,"PoST");if e!=nil{return nil,e};if e=p.end();e!=nil{return nil,e};if e=p.expect("}");e!=nil{return nil,e}
			ir.Declarations=append(ir.Declarations,Declaration{Kind:"right",Name:n,Requires:[]Requirement{req}})
		case "activity":
			p.take(); n,e:=p.identifier();if e!=nil{return nil,e};if seen["activity:"+n]{return nil,fmt.Errorf("duplicate activity %q",n)};seen["activity:"+n]=true
			if e=p.block();e!=nil{return nil,e};if _,e=p.expect("requires");e!=nil{return nil,e};req,e:=parseProof(p,"PoAT");if e!=nil{return nil,e};if e=p.end();e!=nil{return nil,e}
			if _,e=p.expect("reward");e!=nil{return nil,e};num:=p.take();if num.Kind!="number"{return nil,fmt.Errorf("line %d: expected integer reward",num.Line)};v,_:=strconv.Atoi(num.Value)
			asset,e:=p.identifier();if e!=nil{return nil,e};if asset!="RIGHTS"{return nil,fmt.Errorf("line %d: unsupported reward asset %q (expected RIGHTS)",num.Line,asset)};if e=p.end();e!=nil{return nil,e};if e=p.expect("}");e!=nil{return nil,e}
			ir.Declarations=append(ir.Declarations,Declaration{Kind:"activity",Name:n,Requires:[]Requirement{req},Reward:&v,Asset:asset})
		case "verify":
			p.take();if ir.ElderQuorum!=0{return nil,fmt.Errorf("duplicate verify block")};if e:=p.block();e!=nil{return nil,e}
			if _,e:=p.expect("quorum");e!=nil{return nil,e};if _,e:=p.expect("elders");e!=nil{return nil,e};if _,e:=p.expect(">=");e!=nil{return nil,e};num:=p.take();if num.Kind!="number"{return nil,fmt.Errorf("line %d: expected quorum integer",num.Line)};q,_:=strconv.Atoi(num.Value);if q<1{return nil,fmt.Errorf("line %d: quorum must be positive",num.Line)};ir.ElderQuorum=q
			if e:=p.end();e!=nil{return nil,e};if e:=p.expect("}");e!=nil{return nil,e}
		default: t:=p.peek();return nil,fmt.Errorf("line %d: unexpected declaration %q",t.Line,t.Value)
		}
	}
	if _,err=p.expect("}");err!=nil{return nil,err}
	if p.peek().Kind!="eof"{return nil,fmt.Errorf("line %d: unexpected trailing token %q",p.peek().Line,p.peek().Value)}
	if len(ir.Identities)==0{return nil,fmt.Errorf("protocol must declare at least one identity")}
	for _,d:=range ir.Declarations {for _,r:=range d.Requires {if !seen["identity:"+r.Subject]{return nil,fmt.Errorf("%s %q references undeclared identity %q",d.Kind,d.Name,r.Subject)}}}
	return ir,nil
}
func parseProof(p *parser,kind string)(Requirement,error){
	if _,e:=p.expect(kind);e!=nil{return Requirement{},e};if _,e:=p.expect("(");e!=nil{return Requirement{},e};subject,e:=p.identifier();if e!=nil{return Requirement{},e}
	r:=Requirement{Kind:kind,Subject:subject}
	if kind=="PoST"{if _,e=p.expect(",");e!=nil{return r,e};s:=p.take();if s.Kind!="string"{return r,fmt.Errorf("line %d: PoST status must be a string",s.Line)};r.Status=strings.Trim(s.Value,"\"")}
	if _,e=p.expect(")");e!=nil{return r,e};return r,nil
}
func Compile(source string)([]byte,error){ir,err:=Parse(source);if err!=nil{return nil,err};return json.MarshalIndent(ir,"","  ")}
