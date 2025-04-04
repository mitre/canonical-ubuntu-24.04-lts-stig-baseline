control 'SV-270733' do
  title 'Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.  
  
Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.  
  
Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'Determine if the field "ocredit" is set in the "/etc/security/pwquality.conf" file with the following command: 
 
$ grep -i "ocredit" /etc/security/pwquality.conf
ocredit=-1 
 
If the "ocredit" parameter is greater than "-1", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to enforce password complexity by requiring that at least one special character be used.  
 
Add or update the following line in the "/etc/security/pwquality.conf" file to include the "ocredit=-1" parameter: 
 
ocredit=-1'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag gid: 'V-270733'
  tag rid: 'SV-270733r1066688_rule'
  tag stig_id: 'UBTU-24-400330'
  tag fix_id: 'F-74667r1066687_fix'
  tag cci: ['CCI-001619', 'CCI-004065', 'CCI-004066']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (g)', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  # value = input('ocredit')
  setting = 'ocredit'

  describe 'pwquality.conf settings' do
    let(:config) { parse_config_file('/etc/security/pwquality.conf', multiple_values: true) }
    let(:setting_value) { config.params[setting].is_a?(Integer) ? [config.params[setting]] : Array(config.params[setting]) }

    it "has `#{setting}` set" do
      expect(setting_value).not_to be_empty, "#{setting} is not set in pwquality.conf"
    end

    it "only sets `#{setting}` once" do
      expect(setting_value.length).to eq(1), "#{setting} is commented or set more than once in pwquality.conf"
    end

    it "does not set `#{setting}` to a positive value" do
      expect(setting_value.first.to_i).to be <= 0, "#{setting} is set to a positive value in pwquality.conf"
    end
  end
end
