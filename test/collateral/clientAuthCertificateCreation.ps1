$pfxPassword = ConvertTo-SecureString 'P@ssw0rd!' -Force -AsPlainText

# Self signed, valid, client EKU Certificate
$pfxFilePath = 'validSelfSignedClientEkuCertificate.pfx'
$certificate = New-SelfSignedCertificate `
    -Subject 'CN=Barry Dorrans,OU=SelfSignedValid,DC=idunno,DC=org' `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -NotBefore (Get-Date) `
    -NotAfter (Get-Date).AddYears(5) `
    -CertStoreLocation "cert:CurrentUser\My" `
    -FriendlyName "Valid Self Signed Client EKU" `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")
$certificatePath = 'Cert:\CurrentUser\My\' + ($certificate.ThumbPrint)
Export-PfxCertificate -Cert $certificatePath -FilePath $pfxFilePath -Password $pfxPassword
Remove-Item $certificatePath

# Self signed, valid, server EKU Certificate
$pfxFilePath = 'validSelfSignedServerEkuCertificate.pfx'
$certificate = New-SelfSignedCertificate `
    -Subject 'CN=Barry Dorrans,OU=SelfSignedValid,DC=idunno,DC=org' `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -NotBefore (Get-Date) `
    -NotAfter (Get-Date).AddYears(5) `
    -CertStoreLocation "cert:CurrentUser\My" `
    -FriendlyName "Valid Self Signed Server EKU" `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")
$certificatePath = 'Cert:\CurrentUser\My\' + ($certificate.ThumbPrint)
Export-PfxCertificate -Cert $certificatePath -FilePath $pfxFilePath -Password $pfxPassword
Remove-Item $certificatePath

# Self signed, valid, No EKU Certificate
$pfxFilePath = 'validSelfSignedNoEkuCertificate.pfx'
$certificate = New-SelfSignedCertificate `
    -Subject 'CN=Barry Dorrans,OU=SelfSignedValid,DC=idunno,DC=org' `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -NotBefore (Get-Date) `
    -NotAfter (Get-Date).AddYears(5) `
    -CertStoreLocation "cert:CurrentUser\My" `
    -FriendlyName "Valid Self Signed No EKU Restrictions" `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature
$certificatePath = 'Cert:\CurrentUser\My\' + ($certificate.ThumbPrint)
Export-PfxCertificate -Cert $certificatePath -FilePath $pfxFilePath -Password $pfxPassword
Remove-Item $certificatePath

