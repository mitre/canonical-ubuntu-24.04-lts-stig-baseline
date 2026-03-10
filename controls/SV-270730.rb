control 'SV-270730' do
  title 'Ubuntu 24.04 LTS must enforce 24 hours/1 day as the minimum password lifetime. Passwords for new users must have a 24 hours/1 day minimum password lifetime restriction.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'Verify Ubuntu 24.04 LTS enforces a 24 hours/1 day minimum password lifetime for new user accounts with the following command: 
 
$ grep -i ^PASS_MIN_DAYS /etc/login.defs 
PASS_MIN_DAYS    1 
 
If the "PASS_MIN_DAYS" parameter value is less than "1" or is commented out, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to enforce a 24 hours/1 day minimum password lifetime. 
 
Add or modify the following line in the "/etc/login.defs" file: 
 
PASS_MIN_DAYS    1'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag gid: 'V-270730'
  tag rid: 'SV-270730r1066679_rule'
  tag stig_id: 'UBTU-24-400300'
  tag fix_id: 'F-74664r1066678_fix'
  tag cci: ['CCI-000198', 'CCI-004066', 'CCI-004065']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (h)', 'IA-5 (1) (g)']
  tag 'host'
  tag 'container'

  value = input('pass_min_days')
  setting = input_object('pass_min_days').name.upcase

  describe "/etc/login.defs does not have `#{setting}` configured" do
    let(:config) { login_defs.read_params[setting] }
    it "greater than #{value} day" do
      expect(config).to cmp <= value
    end
  end
end
