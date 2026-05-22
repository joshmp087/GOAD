# https://learn.microsoft.com/fr-fr/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon
if(-not(query session paul.wagner /server:TUC-SRV02)) {
  #kill process if exist
  Get-Process mstsc -IncludeUserName | Where {$_.UserName -eq "TUMAMOC\paul.wagner"}|Stop-Process
  #run the command
  mstsc /v:TUC-SRV02
}
