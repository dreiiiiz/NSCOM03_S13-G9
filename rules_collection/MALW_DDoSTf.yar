rule DDosTf
{
  meta:
    author      = "benkow_ - MalwareMustDie"
    reference   = "http://blog.malwaremustdie.org/2016/01/mmd-0048-2016-ddostf-new-elf-windows.html"
    description = "Rule to detect ELF.DDosTf infection"

  strings:
    $st0 = "ddos.tf"
    $st1 = {E8AEBEE7BDAE5443505F4B454550494E54564CE99499E8AFAFEFBC9A00}
    $st2 = {E8AEBEE7BDAE5443505F4B454550434E54E99499E8AFAFEFBC9A00}
    $st3 = "Accept-Language: zh"
    $st4 = "%d Kb/bps|%d%%"

  condition:
    uint32(0) == 0x464c457f and all of them
}
