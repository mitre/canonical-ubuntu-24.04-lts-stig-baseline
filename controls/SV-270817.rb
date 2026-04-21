control 'SV-270817' do
  title 'Ubuntu 24.04 LTS must have a crontab script running weekly to offload audit events of standalone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Note: If this is an interconnected system, this is not applicable.

Verify there is a script that offloads audit data and that script runs weekly with the following command:

$ ls /etc/cron.weekly
audit-offload

Check if the script inside the file offloads audit logs to external media.

If the script file does not exist or does not offload audit logs, this is a finding.'
  desc 'fix', 'Create a script that offloads audit logs to external media and runs weekly.

The script must be located in the "/etc/cron.weekly" directory.'
  impact 0.3
  tag check_id: 'C-74850r1066938_chk'
  tag severity: 'low'
  tag gid: 'V-270817'
  tag rid: 'SV-270817r1066940_rule'
  tag stig_id: 'UBTU-24-900950'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-74751r1066939_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers or airgapped systems', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) && !input('airgapped_system')
  }

  cron_file = input('audit_offload_script')

  describe file(cron_file) do
    it { should exist }
    it { should be_file }
    it { should be_executable }
    its('content') { should_not be_empty }
  end
end
