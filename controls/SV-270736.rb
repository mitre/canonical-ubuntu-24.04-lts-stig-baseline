control 'SV-270736' do
  title 'Ubuntu 24.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Verify that authenticated certificates are mapped to the appropriate user group in the "/etc/sssd/sssd.conf" file with the following command: 
 
$ grep -i ldap_user_certificate /etc/sssd/sssd.conf
ldap_user_certificate=userCertificate;binary'
  desc 'fix', 'Configure sssd to map authenticated certificates to the appropriate user group by adding the following line to the "/etc/sssd/sssd.conf" file:

ldap_user_certificate=userCertificate;binary'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag gid: 'V-270736'
  tag rid: 'SV-270736r1066697_rule'
  tag stig_id: 'UBTU-24-400370'
  tag fix_id: 'F-74670r1066696_fix'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (c)', 'IA-5 (2) (a) (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('pki_disabled')
    impact 0.0
    describe 'This system is not using PKI for authentication so the controls is Not Applicable.' do
      skip 'This system is not using PKI for authentication so the controls is Not Applicable.'
    end
  else
    config_file = '/etc/pam_pkcs11/pam_pkcs11.conf'
    config_file_exists = file(config_file).exist?

    if config_file_exists
      describe parse_config_file(config_file) do
        its('use_mappers') { should cmp 'pwent' }
      end
    else
      describe("#{config_file} exists") do
        subject { config_file_exists }
        it { should be true }
      end
    end
  end
end
