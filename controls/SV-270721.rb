control 'SV-270721' do
  title 'Ubuntu 24.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include:
1) Something a user knows (e.g., password/PIN);
2) Something a user has (e.g., cryptographic identification device, token); and
3) Something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).

The DOD common access card (CAC) with DOD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify that the "pam_pkcs11.so" module is configured with the following command:

$ grep -r pam_pkcs11.so /etc/pam.d/common-auth
auth    [success=2 default=ignore] pam_pkcs11.so

If the module is not configured, is missing, or commented out, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to use multifactor authentication for access to accounts.

Add or update "pam_pkcs11.so" in "/etc/pam.d/common-auth" to match the following line:

auth    [success=2 default=ignore] pam_pkcs11.so'
  impact 0.5
  tag check_id: 'C-74754r1066650_chk'
  tag severity: 'medium'
  tag gid: 'V-270721'
  tag rid: 'SV-270721r1066652_rule'
  tag stig_id: 'UBTU-24-400020'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-74655r1066651_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768', 'CCI-004047']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)', 'IA-2 (6) (b)']
  tag 'host'

  if %w[docker podman kubepods lxc].include?(virtualization.system)
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  elsif input('pki_disabled')
    impact 0.0
    describe 'This system is not using PKI for authentication so the controls is Not Applicable.' do
      skip 'This system is not using PKI for authentication so the controls is Not Applicable.'
    end
  else
    describe package('libpam-pkcs11') do
      it { should be_installed }
    end

    describe pam('/etc/pam.d/common-auth') do
      its('lines') { should match_pam_rule('auth [success=2 default=ignore] pam_pkcs11.so') }
    end
  end
end
