# https://learn.microsoft.com/fr-fr/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon
if(-not(query session paul.wagner /server:MKT-WEB01)) {
  #kill process if exist
  Get-Process mstsc -IncludeUserName | Where {$_.UserName -eq "MARKETING\paul.wagner"}|Stop-Process
  #run the command
  mstsc /v:MKT-WEB01
}
