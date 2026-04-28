control 'SV-270677' do
  title 'Ubuntu 24.04 LTS must limit the number of concurrent sessions to 10 for all accounts and/or account types.'
  desc 'Ubuntu 24.04 LTS management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to denial-of-service (DoS) attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions must be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Verify Ubuntu 24.04 LTS limits the number of concurrent sessions to 10 for all accounts and/or account types with the following command:

$ grep -r maxlogins /etc/security/limits.conf /etc/security/limits.d/*.conf
/etc/security/limits.d/maxlogins.conf:* hard maxlogins 10

If the "maxlogins" item does not have a value of "10" or less, is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to limit the number of concurrent sessions to 10 for all accounts and/or account types.

Add the following line to the top of the /etc/security/limits.conf or in a ".conf" file defined in /etc/security/limits.d/:

* hard maxlogins 10'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag gid: 'V-270677'
  tag rid: 'SV-270677r1101774_rule'
  tag stig_id: 'UBTU-24-200000'
  tag fix_id: 'F-74611r1066519_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  setting = 'maxlogins'
  expected_value = input('concurrent_sessions_permitted')

  limits_files = command('ls /etc/security/limits.d/*.conf').stdout.strip.split
  limits_files.append('/etc/security/limits.conf')

  # make sure that at least one limits.conf file has the correct setting
  globally_set = limits_files.any? { |lf| !limits_conf(lf).read_params['*'].nil? && limits_conf(lf).read_params['*'].include?(['hard', setting.to_s, expected_value.to_s]) }

  # make sure that no limits.conf file has a value that contradicts the global set
  failing_files = limits_files.select { |lf|
    limits_conf(lf).read_params.values.flatten(1).any? { |l|
      l[1].eql?(setting) && l[2].to_i > expected_value
    }
  }
  describe 'Limits files' do
    it "should limit concurrent sessions to #{expected_value} by default" do
      expect(globally_set).to eq(true), "No global ('*') setting for concurrent sessions found"
    end
    it 'should not have any conflicting settings' do
      expect(failing_files).to be_empty, "Files with incorrect '#{setting}' settings:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
