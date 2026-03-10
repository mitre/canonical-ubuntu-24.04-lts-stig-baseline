control 'SV-270807' do
  title 'Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers file occur.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates audit records for all modifications that affect "/etc/sudoers" with the following command: 
 
$ sudo auditctl -l | grep sudoers
-w /etc/sudoers -p wa -k privilege_modification 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to generate audit records for all modifications that affect "/etc/sudoers".  

Add or update the following rule to "/etc/audit/rules.d/stig.rules": 

-w /etc/sudoers -p wa -k privilege_modification 

To reload the rules file, issue the following command: 

$ sudo augenrules --load'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000466-GPOS-00210'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000004-GPOS-00004', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000304-GPOS-00121', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'CCI-002884', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000476-GPOS-00221']
  tag gid: 'V-270807'
  tag rid: 'SV-270807r1066910_rule'
  tag stig_id: 'UBTU-24-900510'
  tag fix_id: 'F-74741r1066909_fix'
  tag cci: ['CCI-000169', 'CCI-000018', 'CCI-000130', 'CCI-000135', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130', 'CCI-002132', 'CCI-002884']
  tag nist: ['AU-12 a', 'AC-2 (4)', 'AU-3 a', 'AU-3 (1)', 'AU-12 c', 'MA-4 (1) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_command = '/etc/sudoers'

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('w', 'a')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
