# https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained#with-protocol-transition
Set-ADUser -Identity "connor.larson" -ServicePrincipalNames @{Add='CIFS/TUC-DC02.tumamoc.cybersaguaros.local'}
Get-ADUser -Identity "connor.larson" | Set-ADAccountControl -TrustedToAuthForDelegation $true
Set-ADUser -Identity "connor.larson" -Add @{'msDS-AllowedToDelegateTo'=@('CIFS/TUC-DC02.tumamoc.cybersaguaros.local','CIFS/TUC-DC02')}
