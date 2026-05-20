Get-ADUser -Identity "brandon.sproles" | Set-ADAccountControl -DoesNotRequirePreAuth:$true
