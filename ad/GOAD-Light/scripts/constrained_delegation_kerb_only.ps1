# https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained#without-protocol-transition
Set-ADComputer -Identity "TUC-SRV02$" -ServicePrincipalNames @{Add='HTTP/TUC-DC02.tumamoc.cybersaguaros.local'}
Set-ADComputer -Identity "TUC-SRV02$" -Add @{'msDS-AllowedToDelegateTo'=@('HTTP/TUC-DC02.tumamoc.cybersaguaros.local','HTTP/TUC-DC02')}
# Set-ADComputer -Identity "TUC-SRV02$" -Add @{'msDS-AllowedToDelegateTo'=@('CIFS/TUC-DC02.tumamoc.cybersaguaros.local','CIFS/TUC-DC02')}
