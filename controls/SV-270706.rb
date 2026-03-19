control 'SV-270706' do
  title 'Ubuntu 24.04 LTS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.

The delay option is set in microseconds.'
  desc 'check', 'Verify Ubuntu 24.04 LTS enforces a delay of at least four seconds between logon prompts following a failed logon attempt with the following command:

$ grep pam_faildelay /etc/pam.d/common-auth
auth    required    pam_faildelay.so    delay=4000000

If the value for "delay" is not set to "4000000" or greater, the line is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to enforce a delay of at least four seconds between logon prompts following a failed logon attempt.

Edit the file "/etc/pam.d/common-auth" and set the parameter "pam_faildelay" to a value of "4000000" or greater:

auth    required    pam_faildelay.so    delay=4000000'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag gid: 'V-270706'
  tag rid: 'SV-270706r1068361_rule'
  tag stig_id: 'UBTU-24-300017'
  tag fix_id: 'F-74640r1066606_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  if %w[docker podman kubepods lxc].include?(virtualization.system)
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe file('/etc/pam.d/common-auth') do
      it { should exist }
    end

    describe command('grep pam_faildelay /etc/pam.d/common-auth') do
      its('exit_status') { should eq 0 }
      its('stdout.strip') { should match(/^\s*auth\s+required\s+pam_faildelay.so\s+.*delay=([4-9]\d{6,}|[1-9]\d{7,}).*$/) }
    end

    file('/etc/pam.d/common-auth').content.to_s.scan(/^\s*auth\s+required\s+pam_faildelay.so\s+.*delay=(\d+).*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 4_000_000 }
      end
    end
  end
end
