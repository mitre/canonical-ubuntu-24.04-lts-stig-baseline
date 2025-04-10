control 'SV-270800' do
  title 'Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the gpasswd command.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify that an audit event is generated for any successful/unsuccessful use of the "gpasswd" command with the following command:
 
$ sudo auditctl -l | grep -w gpasswd
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-gpasswd 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "gpasswd" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-gpasswd 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74833r1066887_chk'
  tag severity: 'medium'
  tag gid: 'V-270800'
  tag rid: 'SV-270800r1066889_rule'
  tag stig_id: 'UBTU-24-900290'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-74734r1066888_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  audit_command = '/usr/bin/gpasswd'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.action.uniq).to cmp 'always'
      expect(audit_rule.list.uniq).to cmp 'exit'
      expect(audit_rule.fields.flatten).to include('perm=x', 'auid>=1000', 'auid!=-1')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
