Get-ChildItem -Path cert:\LocalMachine -Recurse | 

#STANDARD FIELDS
Select-Object PSParentPath, `
FriendlyName, `
@{Name='EnhancedKeyUsageList';Expression={$_.EnhancedKeyUsageList}},
@{Name='ssl_issuer';Expression={$_.IssuerName.name}},
@{Name='ssl_end_time';Expression={$_.NotAfter}},
@{Name='ssl_start_time';Expression={$_.NotBefore}},
@{Name='ssl_serial';Expression={$_.SerialNumber}},
@{Name='ssl_publickey_algorithm';Expression={$_.PublicKey.EncodedKeyValue.Oid.FriendlyName}},
@{N='Public_Key_Size';E={$_.PublicKey.key.keysize}},
@{Name='Encoded_Key_Parameters';Expression={foreach($value in $_.PublicKey.EncodedParameters.RawData){$value.ToString('X2')}}},
@{N='Public_Key_Algorithm';E={$_.PublicKey.Oid.FriendlyName}},
@{Name='ssl_signature_algorithm';Expression={$_.SignatureAlgorithm.FriendlyName}},
Thumbprint,
@{Name='ssl_version';Expression={$_.Version}},
@{Name='ssl_subject';Expression={$_.Subject}},
@{Name='ssl_publickey';Expression={foreach($value in $_.PublicKey.EncodedKeyValue.RawData){$value.ToString('X2')}}}, `

#EXTENSIONS
@{N="ssl_ext_Unique_Identifiers";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Unique Identifiers"}).Format(0)}},`
@{N="ssl_ext_Authority_Key_Identifier";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Authority Key Identifier"}).Format(0)}},`
@{N="ssl_ext_Subject_Key_Identifier";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Subject Key Identifier"}).Format(0)}},`
@{N="ssl_ext_Key_Usage";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Key Usage"}).Format(0)}},`
@{N="ssl_ext_Certificate_Policies";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Certificate Policies"}).Format(0)}},`
@{N="ssl_ext_Policy_Mappings";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Policy Mappings"}).Format(0)}},`
@{N="ssl_ext_Subject_Alternative_Name";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Subject Alternate Name"}).Format(0)}},`
@{N="ssl_ext_Issuer_Alternate_Name";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Issuer Alternate Name"}).Format(0)}},`
@{N="ssl_ext_Subject_Directory_Attributes";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Subject Directory Attributes"}).Format(0)}},`
@{N="ssl_ext_Basic_Constraints";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Basic Constraints"}).Format(0)}},`
@{N="ssl_ext_Name_Constraints";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Name Constraints"}).Format(0)}},`
@{N="ssl_ext_Policy_Constraints";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Policy Constraints"}).Format(0)}},`
@{N="ssl_ext_Extended_Key_Usage";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Extended Key Usage"}).Format(0)}},`
@{N="ssl_ext_CRL_Distribution_Points";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "CRL Distribution Points"}).Format(0)}},`
@{N="ssl_ext_Inhibit_Policy";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Inhibit Policy"}).Format(0)}},`
@{N="ssl_ext_Freshest_CRL";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Freshest CRL"}).Format(0)}},`
@{N="ssl_pri_ext_Authority_Information_Access";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Authority Information Access"}).Format(0)}},`
@{N="ssl_pri_ext_Subject_Information_Access";E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Subject Information Access"}).Format(0)}} |`
Export-Csv .\certificateList.csv -notype