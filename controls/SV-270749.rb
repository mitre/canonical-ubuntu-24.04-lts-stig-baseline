control 'SV-270749' do
  title 'Ubuntu 24.04 LTS must restrict access to the kernel message buffer.'
  desc 'Restricting access to the kernel message buffer limits access only to root. This prevents attackers from gaining additional system information as a nonprivileged user.'
  desc 'check', 'Verify Ubuntu 24.04 LTS is configured to restrict access to the kernel message buffer with the following command:

$ sysctl kernel.dmesg_restrict
kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding.

Verify there are no configurations that enable the kernel dmesg function:

$ sudo grep -r kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
/etc/sysctl.d/10-kernel-hardening.conf:kernel.dmesg_restrict = 1

If any instance of "kernel.dmesg_restrict" is uncommented and set to "0", or if conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to restrict access to the kernel message buffer.

Set the system to the required kernel parameter by adding or modifying the following line in /etc/sysctl.conf or a config file in the /etc/sysctl.d/ directory:

     kernel.dmesg_restrict = 1

Remove any configurations that conflict with the above from the following locations: 
     /run/sysctl.d/
     /etc/sysctl.d/
     /usr/local/lib/sysctl.d/
     /usr/lib/sysctl.d/
     /lib/sysctl.d/
     /etc/sysctl.conf

Reload settings from all system configuration files with the following command:

     $ sudo sysctl --system'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag gid: 'V-270749'
  tag rid: 'SV-270749r1137695_rule'
  tag stig_id: 'UBTU-24-600140'
  tag fix_id: 'F-74683r1066735_fix'
  tag cci: ['CCI-001090', 'CCI-001082']
  tag nist: ['SC-4', 'SC-2']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'kernel.dmesg_restrict'
  value = 1
  regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

  describe kernel_parameter(parameter) do
    its('value') { should eq value }
  end

  search_results = command("/usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F #{parameter}").stdout.strip.split("\n")

  correct_result = search_results.any? { |line| line.match(regexp) }
  incorrect_results = search_results.map(&:strip).reject { |line| line.match(regexp) }

  describe 'Kernel config files' do
    it "should configure '#{parameter}'" do
      expect(correct_result).to eq(true), 'No config file was found that correctly sets this action'
    end
    unless incorrect_results.nil?
      it 'should not have incorrect or conflicting setting(s) in the config files' do
        expect(incorrect_results).to be_empty, "Incorrect or conflicting setting(s) found:\n\t- #{incorrect_results.join("\n\t- ")}"
      end
    end
  end
end
