static const struct { const char *in, *hex; } filter_vectors[] = {
  {"(uid=alice)", "a30c04037569640405616c696365"},
  {"(&(objectclass=groupOfNames)(member=cn=a,dc=x))", "a032a31b040b6f626a656374636c617373040c67726f75704f664e616d6573a31304066d656d6265720409636e3d612c64633d78"},
  {"(|(a=1)(b=2)(!(c=3)))", "a11aa306040161040131a306040162040132a208a306040163040133"},
  {"(cn=*)", "8702636e"},
  {"(cn=a*)", "a4090402636e3003800161"},
  {"(cn=*b)", "a4090402636e3003820162"},
  {"(cn=a*b*c)", "a40f0402636e3009800161810162820163"},
  {"(cn=*mid*)", "a40b0402636e300581036d6964"},
  {"(cn>=5)", "a5070402636e040135"},
  {"(cn<=5)", "a6070402636e040135"},
  {"(cn~=x)", "a8070402636e040178"},
  {"(cn=\\28x\\29)", "a3090402636e0403287829"},
  {"(cn=a\\2ab*)", "a40b0402636e30058003612a62"},
  {"(sAMAccountName=bob\\28\\2a\\29\\5c\\c3\\a9)", "a31b040e73414d4163636f756e744e616d650409626f62282a295cc3a9"},
  {"(&(uid=x)(|(memberOf=cn=g,dc=x)(cn=y)))", "a02ca3080403756964040178a120a31504086d656d6265724f660409636e3d672c64633d78a3070402636e040179"},
  {"(cn=)", "a3060402636e0400"},
  {"(&)", "a000"},
};
static const char *bad_filters[] = {
  "uid=x",
  "(uid=x",
  "(uid=x))",
  "(cn=\\zz)",
};
static const struct { const char *in, *out; } dn_vectors[] = {
  {"uid=Alice,OU=People,DC=Example,DC=com", "uid=Alice,ou=People,dc=Example,dc=com"},
  {"CN=Smith\\, John,dc=x", "cn=Smith\\, John,dc=x"},
  {" cn = a b , dc = x ", "cn=a b,dc=x"},
  {"cn=b+sn=a,dc=x", "cn=b+sn=a,dc=x"},
  {"sn=a+cn=b;dc=x", "cn=b+sn=a,dc=x"},
  {"cn=\\23hash,dc=x", "cn=\\#hash,dc=x"},
  {"cn=#04024869,dc=x", "cn=Hi,dc=x"},
  {"cn=Lu\\C4\\8Di\\C4\\87,o=x", "cn=Lu\\c4\\8di\\c4\\87,o=x"},
  {"cn=trailing\\ ,dc=x", "cn=trailing\\ ,dc=x"},
  {"cn=a\\=b,dc=x", "cn=a=b,dc=x"},
  {"cn=x<y,dc=q", "cn=x\\<y,dc=q"},
  {"", ""},
  {"cn=é,dc=x", "cn=\\c3\\a9,dc=x"},
};
static const char *bad_dns[] = {
  "cn",
  "cn=a,",
  "cn=\\zz",
  "cn=a\\",
};
static const char *escape_in = "a(b)*c\\dé", *escape_out = "a\\28b\\29\\2ac\\5cd\\c3\\a9";
