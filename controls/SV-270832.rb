control 'SV-270832' do
  title 'Ubuntu 24.04 LTS audit system must protect auditing rules from unauthorized change.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality. Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit Ubuntu 24.04 LTS system activity. In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back. A system reboot would be noticeable, and a system administrator could then investigate the unauthorized changes.'
  desc 'check', %q(Verify the running audit system prevents unauthorized changes (is immutable) with the following command:

$ sudo auditctl -s | grep "enabled"
enabled 2

If the "enabled" value returned is not "2", this is a finding.

Verify that the audit system is configured to be immutable across reboots with the following command:

$ grep -E '^-e 2' /etc/audit/rules.d/*.rules
/etc/audit/rules.d/99-finalize.rules:-e 2

If the "-e 2" option is not configured in a rules file under "/etc/audit/rules.d/", this is a finding.)
  desc 'fix', 'Configure the audit system to set the audit rules to be immutable by performing the following steps:

Create or edit a finalized rules file (e.g., "/etc/audit/rules.d/99-finalize.rules") and append the following option as the absolute last line:

-e 2

Compile and load the new rules into the active kernel:

$ sudo augenrules --load

Note: Once this rule is active, further changes to the audit configuration will be blocked. A system reboot will be required to apply any future audit rule modifications.'
  impact 0.5
  tag check_id: 'C-74865r1261486_chk'
  tag severity: 'medium'
  tag gid: 'V-270832'
  tag rid: 'SV-270832r1261488_rule'
  tag stig_id: 'UBTU-24-909000'
  tag gtitle: 'SRG-OS-000058-GPOS-00028'
  tag fix_id: 'F-74766r1261487_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  describe 'The running audit system' do
    subject { command('auditctl -s').stdout }
    it 'should be immutable (enabled 2)' do
      expect(subject).to match(/^enabled\s+2$/)
    end
  end

  rules_files = command("find /etc/audit/rules.d -maxdepth 1 -type f -name '*.rules' -printf '%p\\n' 2>/dev/null").stdout.split("\n").reject(&:empty?)
  immutable_files = rules_files.select { |f| file(f).content.to_s.match?(/^-e\s+2\b/) }

  describe 'The audit rules in /etc/audit/rules.d/' do
    it 'should set the immutable option (-e 2) so it persists across reboots' do
      expect(immutable_files).not_to be_empty, "No '-e 2' line found in:\n\t- #{rules_files.join("\n\t- ")}"
    end
  end
end
