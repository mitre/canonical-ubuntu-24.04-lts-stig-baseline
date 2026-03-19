control 'SV-270761' do
  title 'Ubuntu 24.04 LTS must configure the directories used by the system journal to be group-owned by "systemd-journal".'
  desc "Only authorized personnel are to be made aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Ubuntu 24.04 LTS or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the /run/log/journal and /var/log/journal directories are group-owned by "systemd-journal" with the following command:

$ sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %G" {} \\;
/run/log/journal systemd-journal
/var/log/journal systemd-journal
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e systemd-journal

If any output returned is not group-owned by "systemd-journal", this is a finding.'
  desc 'fix', 'Configure the system to set the appropriate group-ownership to the directories used by the systemd journal:

$ sudo nano /usr/lib/tmpfiles.d/systemd.conf

Edit the following lines of the configuration file:

z /run/log/journal 2640 root systemd-journal - -
z /var/log/journal 2640 root systemd-journal - -

Note: The system must be restarted for these settings to take effect.'
  impact 0.5
  tag check_id: 'C-74794r1066770_chk'
  tag severity: 'medium'
  tag gid: 'V-270761'
  tag rid: 'SV-270761r1067180_rule'
  tag stig_id: 'UBTU-24-700060'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-74695r1067180_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  journal_bases  = %w[/run/log/journal /var/log/journal]
  journald_group = 'systemd-journal'

  journal_bases.each do |base|
    describe directory(base) do
      it { should exist }
    end
  end

  failing_dirs = command("find -L #{journal_bases.join(' ')} -type d ! -group #{journald_group} -print 2>/dev/null").stdout.split("\n").reject(&:empty?)

  describe 'Journal directories group-ownership' do
    it "are group-owned by #{journald_group}" do
      expect(failing_dirs).to be_empty, "Directories not group-owned by #{journald_group}:\n\t- #{failing_dirs.join("\n\t- ")}"
    end
  end
end
