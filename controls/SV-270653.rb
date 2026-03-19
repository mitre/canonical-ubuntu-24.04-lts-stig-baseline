control 'SV-270653' do
  title 'Ubuntu 24.04 LTS must be configured to preserve log records from failure events.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system.

Preserving operating system state information helps to facilitate operating system restart and return to the operational mode of the organization with least disruption to mission/business processes.'
  desc 'check', 'Verify the log service is installed properly with the following command:

$ dpkg -l | grep rsyslog
ii  rsyslog     8.2312.0-3ubuntu9      amd64     reliable system and kernel logging daemon

If the "rsyslog" package is not installed, this is a finding.

Check that the log service is enabled with the following command:

$ systemctl is-enabled rsyslog
enabled

If the command above returns "disabled", this is a finding.

Check that the log service is properly running and active on the system with the following command:

$ systemctl is-active rsyslog
active

If the command above returns "inactive", this is a finding.'
  desc 'fix', 'Configure the log service to collect failure events.

Install the log service (if the log service is not already installed) with the following command:

$ sudo apt install -y rsyslog

Enable the log service with the following command:

$ sudo systemctl enable --now rsyslog'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000269-GPOS-00103'
  tag gid: 'V-270653'
  tag rid: 'SV-270653r1067141_rule'
  tag stig_id: 'UBTU-24-100200'
  tag fix_id: 'F-74587r1067140_fix'
  tag cci: ['CCI-000366', 'CCI-000154', 'CCI-001851', 'CCI-001665']
  tag nist: ['CM-6 b', 'AU-6 (4)', 'AU-4 (1)', 'SC-24']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('alternative_logging_method') == ''
    describe package('rsyslog') do
      it { should be_installed }
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
