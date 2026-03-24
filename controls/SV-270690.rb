control 'SV-270690' do
  title 'Ubuntu 24.04 LTS must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', %q(Verify that Ubuntu 24.04 LTS utilizes the "pam_faillock" module with the following command:

$ grep faillock /etc/pam.d/common-auth
auth     [default=die]  pam_faillock.so authfail
auth     sufficient     pam_faillock.so authsucc

If the pam_faillock.so module is not present in the "/etc/pam.d/common-auth" file, this is a finding.

Verify the pam_faillock module is configured to use the following options:

$ sudo egrep 'silent|audit|deny|fail_interval| unlock_time' /etc/security/faillock.conf
audit
silent
deny = 3
fail_interval = 900
unlock_time = 0

If the "silent" keyword is missing or commented out, this is a finding.
If the "audit" keyword is missing or commented out, this is a finding.
If the "deny" keyword is missing, commented out, or set to a value greater than "3", this is a finding.
If the "fail_interval" keyword is missing, commented out, or set to a value greater than "900", this is a finding.
If the "unlock_time" keyword is missing, commented out, or not set to "0", this is a finding.)
  desc 'fix', 'Configure Ubuntu 24.04 LTS to utilize the "pam_faillock" module.

Edit the /etc/pam.d/common-auth file to add the following lines below the "auth" definition for pam_unix.so:
auth     [default=die]  pam_faillock.so authfail
auth     sufficient     pam_faillock.so authsucc

Configure the "pam_faillock" module to use the following options:

Edit the /etc/security/faillock.conf file and add/update the following keywords and values:
audit
silent
deny = 3
fail_interval = 900
unlock_time = 0'
  impact 0.3
  tag check_id: 'C-74723r1067125_chk'
  tag severity: 'low'
  tag gid: 'V-270690'
  tag rid: 'SV-270690r1067126_rule'
  tag stig_id: 'UBTU-24-200610'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-74624r1066558_fix'
  tag satisfies: ['SRG-OS-000329-GPOS-00128', 'SRG-OS-000021-GPOS-00005']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
  tag 'host'
  tag 'container'

  unsuccessful_attempts = input('unsuccessful_attempts')
  fail_interval = input('fail_interval')
  lockout_time = input('lockout_time')

  describe parse_config_file('/etc/security/faillock.conf') do
    its('audit') { should eq '' }
    its('silent') { should eq '' }
    its('deny') { should cmp <= unsuccessful_attempts }
    its('fail_interval') { should cmp <= fail_interval }
    its('unlock_time') { should cmp lockout_time }
  end
end
