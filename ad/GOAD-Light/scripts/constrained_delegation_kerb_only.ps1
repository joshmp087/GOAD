# https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained#without-protocol-transition
Set-ADComputer -Identity "MKT-WEB01$" -ServicePrincipalNames @{Add='HTTP/MKT-DC01.marketing.cybersaguaros.local'}
Set-ADComputer -Identity "MKT-WEB01$" -Add @{'msDS-AllowedToDelegateTo'=@('HTTP/MKT-DC01.marketing.cybersaguaros.local','HTTP/MKT-DC01')}
# Set-ADComputer -Identity "MKT-WEB01$" -Add @{'msDS-AllowedToDelegateTo'=@('CIFS/MKT-DC01.marketing.cybersaguaros.local','CIFS/MKT-DC01')}
