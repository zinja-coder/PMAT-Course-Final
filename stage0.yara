rule stage0{
  meta:
    author = "ZINJA"
    source = "FBI"
    sharing = "TLP:CLEAR"
    status = "RELEASED"
    description = "Yara rule to detect stage0.exe from PMAT course"
    category = "MALWARE"
    creation_date = "2024-04-23"
  strings:
     $werflt1 = "@C:\Users\Public\werflt.exe"
     $werflt2 = "@C:\Windows\SysWOW64\WerFault.exe"
     $werflt3 = "C:\Users\Administrator\source\repos\CRTInjectorConsole\Release\CRTInjectorConsole.pdb"
  condition:
    all of them

}
