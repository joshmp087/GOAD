# https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained#with-protocol-transition
Set-ADUser -Identity "connor.larson" -ServicePrincipalNames @{Add='CIFS/MKT-DC01.marketing.cybersaguaros.local'}
Get-ADUser -Identity "connor.larson" | Set-ADAccountControl -TrustedToAuthForDelegation $true
Set-ADUser -Identity "connor.larson" -Add @{'msDS-AllowedToDelegateTo'=@('CIFS/MKT-DC01.marketing.cybersaguaros.local','CIFS/MKT-DC01')}
