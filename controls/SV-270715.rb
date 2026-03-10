control 'SV-270715' do
  title 'Ubuntu 24.04 LTS must generate audit records for all events that affect the systemd journal files.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to modify system level binaries and their operation. Auditing the systemd journal files provides logging that can be used for forensic purposes.
 
To address access requirements, many operating systems may be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates audit records for all events that affect "/var/log/journal" with the following command: 
 
$ sudo auditctl -l | grep journal
-w /var/log/journal -p wa -k systemd_journal 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to generate audit records for events that affect "/var/log/journal". 
 
Add or update the following rule to "/etc/audit/rules.d/stig.rules": 
 
-w /var/log/journal -p wa -k systemd_journal 
  
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74748r1066632_chk'
  tag severity: 'medium'
  tag gid: 'V-270715'
  tag rid: 'SV-270715r1066634_rule'
  tag stig_id: 'UBTU-24-300029'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-74649r1066633_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  audit_command = '/var/log/journal'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('w', 'a')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
