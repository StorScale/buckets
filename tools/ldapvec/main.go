package main

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/go-ldap/ldap/v3"
)

func q(s string) string { return strconv.Quote(s) }

func main() {
	filters := []string{
		"(uid=alice)", "(&(objectclass=groupOfNames)(member=cn=a,dc=x))", "(|(a=1)(b=2)(!(c=3)))",
		"(cn=*)", "(cn=a*)", "(cn=*b)", "(cn=a*b*c)", "(cn=*mid*)", "(cn>=5)", "(cn<=5)", "(cn~=x)",
		"(cn=\\28x\\29)", "(cn=a\\2ab*)", "(sAMAccountName=" + ldap.EscapeFilter("bob(*)\\é") + ")",
		"(&(uid=x)(|(memberOf=cn=g,dc=x)(cn=y)))", "(cn=)", "(&)",
	}
	fmt.Println("static const struct { const char *in, *hex; } filter_vectors[] = {")
	for _, f := range filters {
		p, err := ldap.CompileFilter(f)
		if err != nil {
			panic(f + err.Error())
		}
		fmt.Printf("  {%s, %s},\n", q(f), q(hex.EncodeToString(p.Bytes())))
	}
	fmt.Println("};")
	bad := []string{"uid=x", "(uid=x", "(uid=x))", "(cn=\\zz)"}
	fmt.Println("static const char *bad_filters[] = {")
	for _, f := range bad {
		if _, err := ldap.CompileFilter(f); err == nil {
			panic("expected error " + f)
		}
		fmt.Printf("  %s,\n", q(f))
	}
	fmt.Println("};")
	dns := []string{
		"uid=Alice,OU=People,DC=Example,DC=com", "CN=Smith\\, John,dc=x", " cn = a b , dc = x ",
		"cn=b+sn=a,dc=x", "sn=a+cn=b;dc=x", "cn=\\23hash,dc=x", "cn=#04024869,dc=x", "cn=Lu\\C4\\8Di\\C4\\87,o=x",
		"cn=trailing\\ ,dc=x", "cn=a\\=b,dc=x", "cn=x<y,dc=q", "", "cn=é,dc=x",
	}
	fmt.Println("static const struct { const char *in, *out; } dn_vectors[] = {")
	for _, d := range dns {
		p, err := ldap.ParseDN(d)
		if err != nil {
			panic(d + err.Error())
		}
		fmt.Printf("  {%s, %s},\n", q(d), q(p.String()))
	}
	fmt.Println("};")
	baddn := []string{"cn", "cn=a,", "cn=\\zz", "cn=a\\"}
	fmt.Println("static const char *bad_dns[] = {")
	for _, d := range baddn {
		if _, err := ldap.ParseDN(d); err == nil {
			fmt.Printf("  /* parses: %s */\n", q(d))
			continue
		}
		fmt.Printf("  %s,\n", q(d))
	}
	fmt.Println("};")
	fmt.Printf("static const char *escape_in = %s, *escape_out = %s;\n", q("a(b)*c\\dé"), q(ldap.EscapeFilter("a(b)*c\\dé")))
}
