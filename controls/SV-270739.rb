control 'SV-270739' do
  title 'Ubuntu 24.04 LTS must encrypt all stored passwords with a FIPS 140-3 approved cryptographic hashing algorithm.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Verify the shadow password suite configuration is set to encrypt passwords with a FIPS 140-3 approved cryptographic hashing algorithm with the following command:

$ grep -i ENCRYPT_METHOD /etc/login.defs
ENCRYPT_METHOD SHA512

If "ENCRYPT_METHOD" does not equal SHA512 or greater, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to encrypt all stored passwords.

Edit/modify the following line in the "/etc/login.defs" file and set "ENCRYPT_METHOD" to SHA512:

ENCRYPT_METHOD SHA512'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag gid: 'V-270739'
  tag rid: 'SV-270739r1067124_rule'
  tag stig_id: 'UBTU-24-400400'
  tag fix_id: 'F-74673r1066705_fix'
  tag cci: ['CCI-000196', 'CCI-000803']
  tag nist: ['IA-5 (1) (c)', 'IA-7']
  tag 'host'
  tag 'container'

  weak_pw_hash_users = inspec.shadow.where { password !~ /^[*!]{1,2}.*$|^\$6\$.*$|^$/ }.users

  describe 'All stored passwords' do
    it 'should only be hashed with the SHA512 algorithm' do
      message = "Users without SHA512 hashes:\n\t- #{weak_pw_hash_users.join("\n\t- ")}"
      expect(weak_pw_hash_users).to be_empty, message
    end
  end
end
